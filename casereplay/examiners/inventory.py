"""Intake agent: verify each image and list what its file system shows today.

This is the "before" picture. It records the volumes, labels and every live
file with its hash and true content type, so the other agents can compare
what is visible with what was hidden or deleted.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from .. import exfat, fat32, udf
from ..docmeta import document_meta
from ..images import SubStream, file_sha1, find_volumes, open_image
from ..ledger import Case, CaseStore, ImageRef
from ..magic import sniff
from ..models import Evidence, Finding, device_entity, file_entity, to_iso
from ..util import head16, human, sha256

AGENT = "inventory"
Log = Callable[[str], None]
MAX_HASH_FILE = 256 * 1024 * 1024
MAX_VERIFY = 1 << 30


def _when(case: Case, dt):
    if dt is None:
        return None
    return to_iso(dt) if dt.tzinfo else case.local_to_iso(dt)


def _listed(case: Case, image: ImageRef, dev, *, name: str, path: str, data: bytes, size: int,
            created, modified, source: str, offset: int, fs: str, time_source: str = "") -> Finding:
    true_type = sniff(data) if data else "EMPTY"
    sha = sha256(data) if data else None
    return Finding(
        kind="file_listed", agent=AGENT,
        title=f"{name} on {image.label}",
        summary=f"{path} ({human(size)}) is a live file on {image.label}. Content type: {true_type}.",
        time=_when(case, created),
        time_source=time_source or f"{fs} created time: when the file was written to this device",
        entities=[dev, file_entity(sha, name)],
        evidence=[Evidence(image=image.name, source=source, path=path, offset=offset, length=size, sha256=sha)],
        confidence=0.99, severity=1, tags=["live"],
        data={"name": name, "path": path, "size": size, "true_type": true_type, "sha256": sha,
              "head16": head16(data), "state": "live",
              "created_local": created.isoformat() if created else None,
              "modified_local": modified.isoformat() if modified else None,
              "doc": document_meta(data, true_type) if data else {}},
    )


def _udf_states(case, image, dev, fh, vol, s, snaps, findings: list[Finding], log: Log) -> int:
    """List what the disc shows now, and log each recorded state of a write-once disc."""
    first_seen: dict[int, object] = {}
    for sn in snaps:
        for key in sn.nodes:
            first_seen.setdefault(key, sn.time)
    live = 0
    for node in snaps[-1].files():
        data = udf.node_bytes(fh, vol.offset, s, node) if node.size <= MAX_HASH_FILE else b""
        sector = node.data_sector(s.partition_start)
        findings.append(_listed(
            case, image, dev, name=node.name, path=node.path, data=data, size=node.size,
            created=first_seen.get(node.vblock) or node.modified, modified=node.modified, fs="UDF",
            source="UDF file entry in the current directory",
            offset=vol.offset + sector * udf.SECTOR if sector is not None else None,
            time_source=("disc session time: when this state of the disc was written (VAT)"
                         if first_seen.get(node.vblock) else "UDF file modification time")))
        live += 1
    if len(snaps) > 1:
        for prev, sn in zip([None] + snaps[:-1], snaps):
            added = [n for k, n in sn.nodes.items() if not n.is_dir and (prev is None or k not in prev.nodes)]
            gone = [n for k, n in (prev.nodes.items() if prev else []) if not n.is_dir and k not in sn.nodes]
            if prev is not None and not added and not gone:
                continue
            if prev is None and not sn.nodes:
                title, text = f"{image.label} prepared for writing", "The disc was formatted with a live file system. It held no files yet."
            elif added:
                size = sum(n.size for n in added) / 1048576
                title = f"{len(added)} file{'s' if len(added) != 1 else ''} burned to {image.label}"
                text = (f"{len(added)} files ({size:.1f} MB) were written to the disc in this session: "
                        + ", ".join(n.name for n in added[:6]) + (f" and {len(added) - 6} more." if len(added) > 6 else "."))
            else:
                continue
            findings.append(Finding(
                kind="cd_burned", agent=AGENT, title=title,
                summary=text + f" This is recorded state {sn.index + 1} of {len(snaps)} on the disc.",
                time=_when(case, sn.time), time_source="VAT write time: each eject of a live disc records a dated state",
                entities=[dev],
                evidence=[Evidence(image=image.name, source="UDF Virtual Allocation Table (VAT) entry",
                                   offset=vol.offset + sn.vat_sector * udf.SECTOR, length=udf.SECTOR,
                                   detail=f"state {sn.index + 1} of {len(snaps)}, sector {sn.vat_sector}")],
                confidence=0.97, severity=2, tags=["disc-session"],
                data={"state": sn.index + 1, "states": len(snaps), "files_added": [n.path for n in added],
                      "files_total": len(sn.files())},
            ))
        log(f"{image.label}: the disc keeps {len(snaps)} dated states from {snaps[0].time} to {snaps[-1].time}")
    return live


def run(case: Case, store: CaseStore, image: ImageRef, log: Log = print) -> list[Finding]:
    findings: list[Finding] = []
    dev = device_entity(image.id, image.label)

    # 1. Integrity. Compare against the hash published with the image.
    if image.sha1_expected and not image.sha1_actual:
        total = sum(p.stat().st_size for p in Path(image.path).parent.glob(Path(image.path).stem + ".*"))
        if total <= MAX_VERIFY:
            image.sha1_actual = file_sha1(image.path)
            store.save_case(case)
    if image.sha1_expected:
        if image.sha1_actual:
            ok = image.sha1_actual.upper() == image.sha1_expected.upper()
            log(f"{image.label}: SHA-1 {'matches' if ok else 'DOES NOT MATCH'} the published value")
            findings.append(Finding(
                kind="system_info", agent=AGENT,
                title=f"{image.label}: image hash {'verified' if ok else 'MISMATCH'}",
                summary=(f"SHA-1 of {image.name} is {image.sha1_actual}. "
                         + ("It matches the value published with the image." if ok
                            else f"Expected {image.sha1_expected}. Do not rely on this copy.")),
                entities=[dev],
                evidence=[Evidence(image=image.name, source="SHA-1 of the image file", detail=image.sha1_actual)],
                confidence=1.0, severity=1 if ok else 3, tags=["integrity"],
                data={"sha1": image.sha1_actual, "expected": image.sha1_expected, "verified": ok},
            ))
        else:
            log(f"{image.label}: large image, hash check left to fetch_dataset.sh")

    if image.kind == "computer":
        log(f"{image.label}: computer image, the activity agent reads it")
        return findings

    fh = open_image(image.path)
    for vol in find_volumes(fh):
        label = ""
        live = 0
        try:
            if vol.fstype == "FAT32":
                v = fat32.Fat32Volume(SubStream(fh, vol.offset, vol.size))
                le = v.volume_label_entry()
                label = (le.name if le else "") or v.bpb.label
                for e in v.walk_live():
                    if e.is_dir:
                        continue
                    data = v.read_live(e) if e.size <= MAX_HASH_FILE else b""
                    findings.append(_listed(
                        case, image, dev, name=e.name, path=e.path, data=data, size=e.size,
                        created=e.created, modified=e.modified, fs="FAT",
                        source="FAT32 directory entry (allocated)",
                        offset=vol.offset + v.bpb.cluster_offset(e.start_cluster)))
                    live += 1
            elif vol.fstype == "EXFAT":
                v = exfat.ExFatVolume(SubStream(fh, vol.offset, vol.size))
                for e in v.walk():
                    if e.is_dir or e.deleted:
                        continue
                    data = v.read_data(e.first_cluster, e.size, e.contiguous) if e.size <= MAX_HASH_FILE else b""
                    findings.append(_listed(
                        case, image, dev, name=e.name, path=e.path, data=data, size=e.size,
                        created=e.created, modified=e.modified, fs="exFAT",
                        source="exFAT directory entry set (in use)",
                        offset=vol.offset + v.cluster_offset(e.first_cluster) if e.first_cluster >= 2 else None))
                    live += 1
                label = v.label
            elif vol.fstype == "UDF":
                s = udf.scan(fh, vol.offset, vol.offset + vol.size if vol.size else None)
                label = s.label
                snaps = udf.snapshots(fh, s, vol.offset)
                if snaps:
                    live = _udf_states(case, image, dev, fh, vol, s, snaps, findings, log)
                for name in ([] if snaps else sorted(s.visible_names())):
                    fe = udf.entry_for(s, name)
                    data = udf.read_file(fh, s, fe, vol.offset) if fe and fe.size <= MAX_HASH_FILE else b""
                    if data and sniff(data) not in ("UNKNOWN", "EMPTY"):
                        findings.append(_listed(
                            case, image, dev, name=name, path="\\" + name, data=data, size=fe.size,
                            created=fe.modified, modified=fe.modified, fs="UDF",
                            source="UDF file entry (newest directory)",
                            offset=vol.offset + (s.partition_start + fe.extents[0][0]) * udf.SECTOR))
                    else:
                        findings.append(Finding(
                            kind="file_listed", agent=AGENT, title=f"{name} on {image.label}",
                            summary=f"{name} is listed in the newest directory on {image.label}.",
                            entities=[dev, file_entity(None, name)],
                            evidence=[Evidence(image=image.name, source="UDF file identifier (newest directory)",
                                               path="\\" + name, offset=s.latest_directory_sector() * udf.SECTOR)],
                            confidence=0.9, severity=1, tags=["live", "name-only"],
                            data={"name": name, "path": "\\" + name, "state": "live"},
                        ))
                    live += 1
        except Exception as exc:  # keep going: a damaged volume is still evidence
            log(f"{image.label}: could not list {vol.fstype} volume ({exc})")
        vol.label = label
        quoted = f' "{label}"' if label else ""
        log(f"{image.label}: {vol.fstype} volume{quoted}, {live} live files")
        findings.append(Finding(
            kind="system_info", agent=AGENT,
            title=f"{image.label}: {vol.fstype} volume" + (f' "{label}"' if label else ""),
            summary=(f"{image.label} holds a {vol.fstype} volume"
                     + (f' labelled "{label}"' if label else "")
                     + f" at byte offset {vol.offset}. The file system shows {live} live files."),
            entities=[dev],
            evidence=[Evidence(image=image.name, source="volume boot record", offset=vol.offset, length=512)],
            confidence=1.0, severity=1, tags=["volume"],
            data={"fstype": vol.fstype, "label": label, "offset": vol.offset, "size": vol.size, "live_files": live},
        ))
    return findings
