"""Recovery agent: bring back files the suspect deleted or lost in a format.

Three deterministic methods:
1. Metadata recovery. On FAT32 we find old directory clusters that survived a
   quick format. On exFAT we read entry sets that are marked deleted. In both
   cases the entry still says where the file starts and how long it is.
2. Old directories on write-once discs. A CD-R cannot erase a name, it can
   only stop listing it. We report names that only older directories show.
3. Carving. Anywhere on the medium, we find file headers and compute each
   file's length from its own structure.
"""
from __future__ import annotations

from typing import Callable

from .. import exfat, fat32, udf
from ..carve import carve
from ..docmeta import document_meta
from ..images import SubStream, find_volumes, open_image
from ..ledger import Case, CaseStore, ImageRef
from ..magic import sniff
from ..models import Evidence, Finding, device_entity, file_entity, to_iso
from ..util import head16, human, safe_name, sha256

AGENT = "recovery"
Log = Callable[[str], None]

_EXT = {"DOC": "doc", "XLS": "xls", "PPT": "ppt", "DOCX": "docx", "XLSX": "xlsx", "PPTX": "pptx",
        "JPEG": "jpg", "PNG": "png", "PDF": "pdf", "ZIP": "zip", "OLE2": "ole"}


def _when(case: Case, dt):
    if dt is None:
        return None
    return to_iso(dt) if dt.tzinfo else case.local_to_iso(dt)


def _recovered(case, image, dev, out_dir, *, name, path, data, size, created, modified, source,
               detail, offset, method, fs, deleted_flag, time_source: str = "", extra: dict | None = None) -> Finding:
    true_type = sniff(data)
    sha = sha256(data)
    target = out_dir / f"{sha[:10]}_{safe_name(name)}"
    target.write_bytes(data)
    intact = true_type not in ("UNKNOWN", "EMPTY")
    return Finding(
        kind="deleted_file_recovered", agent=AGENT,
        title=f"Recovered {name}",
        summary=(f"{path} ({human(size)}) was recovered from {image.label}. "
                 f"{detail} Content type: {true_type}."),
        time=_when(case, created),
        time_source=time_source or f"{fs} created time: when the file was written to this device",
        entities=[dev, file_entity(sha, name)],
        evidence=[Evidence(image=image.name, source=source, path=path, offset=offset, length=len(data),
                           sha256=sha, extracted_to=f"recovered/{image.id}/{target.name}")],
        confidence=0.95 if intact else 0.5, severity=2,
        tags=["recovered", method] + (["entry-deleted"] if deleted_flag else []),
        data={"name": name, "path": path, "size": size, "true_type": true_type, "sha256": sha,
              "head16": head16(data), "intact": intact, "method": method, "state": "deleted",
              "created_local": created.isoformat() if created else None,
              "modified_local": modified.isoformat() if modified else None,
              "doc": document_meta(data, true_type), **(extra or {})},
    )


def _office_lock(case, image, dev, *, name: str, path: str, data: bytes, created, siblings: list[str],
                 source: str, offset, fs: str) -> Finding | None:
    """Office leaves a tiny lock file next to a document while it is open. Its creation time is when the
    document was opened, and it names the Office user. Word swaps the first two letters for "~$"."""
    if not name.startswith("~$") or not 40 <= len(data) <= 256:
        return None
    n = data[0]
    user = data[1: 1 + n].decode("cp1252", "replace").strip() if 0 < n < 54 else ""
    doc = next((x for x in siblings if not x.startswith("~$") and x[2:].lower() == name[2:].lower()), None)
    shown = doc or ("??" + name[2:])
    return Finding(
        kind="file_opened", agent=AGENT, title=f"{shown} was opened in Office from {image.label}",
        summary=(f"Office keeps a small lock file next to a document while it is open. The lock file {path} was "
                 f"created on {image.label}, so {shown} was opened directly from this device"
                 + (f" by the Office user \"{user}\"" if user else "")
                 + ". The lock file was deleted when the document closed and has been recovered."),
        time=_when(case, created), time_source=f"{fs} created time of the Office lock file: when the document was opened",
        entities=[dev, file_entity(None, shown)],
        evidence=[Evidence(image=image.name, source=source, path=path, offset=offset, length=len(data),
                           sha256=sha256(data), detail=f"lock file owner: {user}" if user else None)],
        confidence=0.9, severity=2, tags=["office-lock", "recovered"],
        data={"name": shown, "target": path, "user": user, "lock_file": name},
    )


def _fit_layout(pairs: list[tuple[int, int]]) -> tuple[int, int] | None:
    """Find (base, cluster_size) such that offset = base + cluster_size * cluster for every pair.

    Pairs come from stale directory entries matched to carved files of exactly the same size. When they
    all fall on one line, the entries belong to an earlier format of the same medium.
    """
    pairs = sorted(set(pairs))
    for (c1, o1), (c2, o2) in zip(pairs, pairs[1:]):
        if c2 == c1 or (o2 - o1) % (c2 - c1):
            continue
        size = (o2 - o1) // (c2 - c1)
        if size < 512 or size & (size - 1):
            continue
        base = o1 - size * c1
        if sum(1 for c, o in pairs if base + size * c == o) >= max(3, len(pairs) - 1):
            return base, size
    return None


def _udf_history(case, image, dev, out_dir, fh, vol, s, snaps, findings: list[Finding],
                 taken: list[tuple[int, int]], log: Log) -> None:
    """Replay a write-once disc from its chain of VATs and recover everything it no longer lists."""
    last = snaps[-1]
    first_seen: dict[int, tuple] = {}
    latest: dict[int, tuple] = {}
    for sn in snaps:
        for key, node in sn.nodes.items():
            first_seen.setdefault(key, (sn, node))
            latest[key] = (sn, node)
    removed_at = {}
    for prev, sn in zip(snaps[:-1], snaps[1:]):
        for key in prev.nodes:
            if key not in sn.nodes:
                removed_at[key] = sn

    def spans(node):
        return [(vol.offset + (s.partition_start + b) * udf.SECTOR, vol.offset + (s.partition_start + b) * udf.SECTOR + n)
                for b, n in node.extents]

    for node in last.files():
        taken.extend(spans(node))                              # still listed: not a recovery
    n0 = len(findings)
    for key, (sn_last, node) in sorted(latest.items()):
        if node.is_dir or key in last.nodes:
            continue
        sn_first, born = first_seen[key]
        gone = removed_at.get(key)
        data = udf.node_bytes(fh, vol.offset, s, node)
        if not data:
            continue
        taken.extend(spans(node))
        sector = node.data_sector(s.partition_start)
        was = f" It was last listed as {node.path}." if node.path != born.path else ""
        when_gone = f" and removed from the directory at {gone.time:%H:%M:%S}" if gone and gone.time else ""
        f = _recovered(
            case, image, dev, out_dir, name=node.name, path=born.path, data=data, size=node.size,
            created=sn_first.time or node.modified, modified=node.modified, fs="UDF",
            source="UDF file entry reached through an earlier VAT (older state of the disc)",
            detail=(f"The disc listed it from {sn_first.time:%H:%M:%S}{when_gone}.{was} "
                    "A write-once disc cannot erase a file, it only stops listing it."
                    if sn_first.time else "An older state of the disc lists it. The current one does not."),
            offset=vol.offset + sector * udf.SECTOR if sector is not None else None,
            method="udf-vat-history", deleted_flag=True,
            time_source="disc session time: when the state that first lists this file was written (VAT)",
            extra={"last_path": node.path, "removed_at": _when(case, gone.time) if gone else None,
                   "fragments": len(node.extents)})
        findings.append(f)
        if gone and gone.time:
            findings.append(Finding(
                kind="file_deleted", agent=AGENT, title=f"{node.name} removed from the disc directory",
                summary=(f"{node.path} was listed on {image.label} in state {gone.index} and is gone in state "
                         f"{gone.index + 1}, written at {gone.time:%Y-%m-%d %H:%M:%S} local time. The content stayed "
                         "on the disc and has been recovered."),
                time=_when(case, gone.time), time_source="VAT write time of the first state without the file",
                entities=[dev, file_entity(f.data["sha256"], node.name)],
                evidence=[Evidence(image=image.name, source="UDF Virtual Allocation Table (VAT) entry",
                                   path=node.path, offset=vol.offset + gone.vat_sector * udf.SECTOR, length=udf.SECTOR,
                                   detail=f"state {gone.index + 1} of {len(snaps)}, sector {gone.vat_sector}")],
                confidence=0.95, severity=2, tags=["udf", "disc-history"],
                data={"name": node.name, "path": node.path, "state": "deleted", "method": "udf-vat-history",
                      "based_on": f.id, "sha256": f.data["sha256"]},
            ))
    for ch in udf.history(snaps):
        if ch.kind == "renamed" and ch.time:
            what = "Folder" if ch.node.is_dir else "File"
            findings.append(Finding(
                kind="file_renamed", agent=AGENT, title=f"{what} {ch.old_name} renamed to {ch.node.name} on the disc",
                summary=(f"{what} {ch.old_name} on {image.label} was renamed to {ch.node.name} at "
                         f"{ch.time:%H:%M:%S} local time."),
                time=_when(case, ch.time), time_source="VAT write time of the state with the new name",
                entities=[dev],
                evidence=[Evidence(image=image.name, source="UDF Virtual Allocation Table (VAT) entry", path=ch.node.path,
                                   offset=vol.offset + snaps[ch.snapshot].vat_sector * udf.SECTOR, length=udf.SECTOR,
                                   detail=f"state {ch.snapshot + 1} of {len(snaps)}")],
                confidence=0.95, severity=2, tags=["udf", "disc-history", "rename"],
                data={"old_name": ch.old_name, "new_name": ch.node.name, "name": ch.node.name, "is_dir": ch.node.is_dir},
            ))
    recovered = sum(1 for f in findings[n0:] if f.kind == "deleted_file_recovered")
    log(f"{image.label}: replayed {len(snaps)} recorded states of the disc, recovered {recovered} files it no longer lists")


def run(case: Case, store: CaseStore, image: ImageRef, log: Log = print) -> list[Finding]:
    findings: list[Finding] = []
    if image.kind == "computer":
        log(f"{image.label}: computer image. Deleted files there are covered by the activity agent "
            "(Recycle Bin and change journal).")
        return findings
    fh = open_image(image.path)
    dev = device_entity(image.id, image.label)
    out_dir = store.recovered_dir(case.id, image.id)

    for vol in find_volumes(fh):
        log(f"{image.label}: {vol.fstype} volume at offset {vol.offset}")
        taken: list[tuple[int, int]] = []
        stale: list = []
        end = vol.offset + vol.size if vol.size else None
        udf_by_offset: dict[int, udf.UdfFile] = {}

        if vol.fstype == "FAT32":
            v = fat32.Fat32Volume(SubStream(fh, vol.offset, vol.size))
            dirs = v.scan_orphan_directories()
            live_dirs = {e.start_cluster for e in v.walk_live() if e.is_dir}
            dirs = [d for d in dirs if d.cluster not in live_dirs]
            log(f"{image.label}: {len(dirs)} old directory clusters survive in unallocated space")
            n0 = len(findings)
            for e in v.iter_recoverable(dirs):
                data = v.read_file(e)
                if not data:
                    continue
                abs_off = vol.offset + v.bpb.cluster_offset(e.start_cluster)
                if sniff(data) in ("UNKNOWN", "EMPTY"):
                    stale.append(e)                    # the entry does not describe what is at that place
                    continue
                taken.append((abs_off, abs_off + len(data)))
                findings.append(_recovered(
                    case, image, dev, out_dir, name=e.name, path=e.path, data=data, size=e.size,
                    created=e.created, modified=e.modified, fs="FAT",
                    source=f"FAT32 directory entry in unallocated cluster {e.dir_cluster}",
                    detail="Its directory entry survived in unallocated space.",
                    offset=abs_off, method="fat-directory-entry", deleted_flag=e.deleted))
            log(f"{image.label}: recovered {len(findings) - n0} files from old directory entries")

        elif vol.fstype == "EXFAT":
            v = exfat.ExFatVolume(SubStream(fh, vol.offset, vol.size))
            n0 = len(findings)
            entries = list(v.walk())
            for e in entries:
                if e.is_dir or not e.deleted or e.size == 0 or e.first_cluster < 2:
                    continue
                data = v.read_data(e.first_cluster, e.size, True)
                if not data:
                    continue
                abs_off = vol.offset + v.cluster_offset(e.first_cluster)
                folder = e.path.rsplit("\\", 1)[0]
                lock = _office_lock(case, image, dev, name=e.name, path=e.path, data=data, created=e.created,
                                    siblings=[x.name for x in entries if x.path.rsplit("\\", 1)[0] == folder],
                                    source="exFAT directory entry set marked deleted", offset=abs_off, fs="exFAT")
                if lock:
                    findings.append(lock)
                    continue
                taken.append((abs_off, abs_off + len(data)))
                findings.append(_recovered(
                    case, image, dev, out_dir, name=e.name, path=e.path, data=data, size=e.size,
                    created=e.created, modified=e.modified, fs="exFAT",
                    source="exFAT directory entry set marked deleted",
                    detail="Its directory entry is marked deleted but still intact.",
                    offset=abs_off, method="exfat-deleted-entry", deleted_flag=True))
            log(f"{image.label}: recovered {len(findings) - n0} deleted files from exFAT entries")

        elif vol.fstype == "UDF":
            try:
                s = udf.scan(fh, vol.offset, end)
                snaps = udf.snapshots(fh, s, vol.offset)
                if snaps:
                    _udf_history(case, image, dev, out_dir, fh, vol, s, snaps, findings, taken, log)
                visible = s.visible_names()
                for f in ([] if snaps else s.files):
                    if f.file_type == 5 and f.extents:
                        off = vol.offset + (s.partition_start + f.extents[0][0]) * udf.SECTOR
                        if any(n.name in visible and not n.deleted_flag for n in f.names):
                            taken.append((off, off + f.size))      # still listed: not a recovery
                        else:
                            udf_by_offset[off] = f
                hidden = [] if snaps else s.hidden_names()
                for n in hidden:
                    findings.append(Finding(
                        kind="file_deleted", agent=AGENT,
                        title=f"{n.name} removed from disc directory",
                        summary=(f"An older directory on {image.label} lists {n.name}. The newest directory does "
                                 "not. A write-once disc cannot erase the file, it only stops listing it."),
                        entities=[dev, file_entity(None, n.name)],
                        evidence=[Evidence(image=image.name, source="UDF file identifier in an older directory",
                                           path="\\" + n.name, offset=n.sector * udf.SECTOR,
                                           detail="deleted flag set" if n.deleted_flag else "absent from newest directory")],
                        confidence=0.85, severity=2, tags=["name-only", "udf"],
                        data={"name": n.name, "path": "\\" + n.name, "state": "deleted", "method": "udf-old-directory"},
                    ))
                if not snaps:
                    log(f"{image.label}: {len(hidden)} file names appear only in older disc directories")
            except Exception as exc:
                log(f"{image.label}: UDF directory scan failed ({exc})")

        if vol.fstype in ("FAT32", "UDF", "UNKNOWN", "FAT16", "EXFAT"):
            if vol.fstype == "EXFAT":
                continue        # live files fill the volume; carving would only repeat them
            n0 = len(findings)
            live_ranges = list(taken)
            if vol.fstype == "FAT32":
                for e in v.walk_live():
                    if not e.is_dir and e.size:
                        o = vol.offset + v.bpb.cluster_offset(e.start_cluster)
                        live_ranges.append((o, o + e.size))
            carved = list(carve(fh, vol.offset, end, skip=live_ranges))
            if stale:
                by_size = {c.size: c.offset for c in carved}
                layout = _fit_layout([(e.start_cluster, by_size[e.size]) for e in stale if e.size in by_size])
                unresolved = []
                for e in stale:
                    off = layout[0] + layout[1] * e.start_cluster if layout else None
                    data = b""
                    if off is not None and vol.offset <= off < (end or off + 1):
                        fh.seek(off)
                        data = fh.read(e.size)
                    if not data or sniff(data) in ("UNKNOWN", "EMPTY"):
                        unresolved.append(e)
                        continue
                    carved = [c for c in carved if c.offset != off]
                    findings.append(_recovered(
                        case, image, dev, out_dir, name=e.name, path=e.path, data=data, size=e.size,
                        created=e.created, modified=e.modified, fs="FAT",
                        source=f"FAT directory entry from an earlier format, in unallocated cluster {e.dir_cluster}",
                        detail=(f"Its directory entry belongs to an earlier format of this medium with "
                                f"{layout[1] // 1024} KB clusters. The file was read where that layout puts it."),
                        offset=off, method="fat-previous-layout", deleted_flag=e.deleted))
                if layout:
                    log(f"{image.label}: {len(stale) - len(unresolved)} more files recovered through an earlier format "
                        f"of the medium ({layout[1] // 1024} KB clusters)")
                for e in unresolved:
                    findings.append(Finding(
                        kind="file_deleted", agent=AGENT, title=f"{e.name} was once on {image.label}",
                        summary=(f"An old directory entry names {e.path} ({human(e.size)}), but the place it points "
                                 "to no longer holds that file. The name and dates are evidence the file existed. "
                                 "The content could not be recovered."),
                        time=_when(case, e.created), time_source="FAT created time in the old directory entry",
                        entities=[dev, file_entity(None, e.name)],
                        evidence=[Evidence(image=image.name, source=f"FAT directory entry in unallocated cluster {e.dir_cluster}",
                                           path=e.path, offset=vol.offset + e.entry_offset, length=32)],
                        confidence=0.6, severity=1, tags=["name-only", "stale-entry"],
                        data={"name": e.name, "path": e.path, "size": e.size, "state": "deleted", "method": "fat-stale-entry"},
                    ))
            n0 = len(findings)
            for c in carved:
                fh.seek(c.offset)
                data = fh.read(c.size)
                name = f"carved_{c.offset:010d}.{_EXT.get(c.type, 'bin')}"
                target = out_dir / name
                target.write_bytes(data)
                meta = document_meta(data, c.type)
                label = meta.get("title") or meta.get("first_text") or name
                uf = udf_by_offset.get(c.offset)
                disc_name = next((n.name for n in uf.names if n.name), None) if uf else None
                written = _when(case, uf.modified) if uf else None
                where = ("No current directory entry points to it." if vol.fstype != "UDF"
                         else (f"An old disc directory names it {disc_name}." if disc_name
                               else "Carving does not depend on the disc directory."))
                findings.append(Finding(
                    kind="carved_file", agent=AGENT,
                    title=f"Carved {disc_name}" if disc_name else f"Carved {c.type} file ({human(c.size)})",
                    summary=(f"A {c.type} file of {human(c.size)} was carved from {image.label} at byte offset "
                             f"{c.offset}. {where}"
                             + (f" The document begins: \"{label[:90]}\"." if label != name else "")),
                    time=written,
                    time_source="UDF file entry modification time" if written else None,
                    entities=[dev, file_entity(c.sha256, disc_name or label[:60])],
                    evidence=[Evidence(image=image.name, source="signature carving (header and internal structure)",
                                       offset=c.offset, length=c.size, sha256=c.sha256, extracted_to=f"recovered/{image.id}/{target.name}")],
                    confidence=0.9 if c.complete else 0.5, severity=2, tags=["recovered", "carved"],
                    data={"name": disc_name or name, "named": bool(disc_name), "size": c.size,
                          "true_type": c.type, "sha256": c.sha256,
                          "head16": head16(data), "intact": c.complete, "method": "carving",
                          "state": "carved", "doc": meta},
                ))
            log(f"{image.label}: carved {len(findings) - n0} more files with no directory entry")
    return findings
