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
               detail, offset, method, fs, deleted_flag) -> Finding:
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
        time_source=f"{fs} created time: when the file was written to this device",
        entities=[dev, file_entity(sha, name)],
        evidence=[Evidence(image=image.name, source=source, path=path, offset=offset, length=len(data),
                           sha256=sha, extracted_to=str(target))],
        confidence=0.95 if intact else 0.5, severity=2,
        tags=["recovered", method] + (["entry-deleted"] if deleted_flag else []),
        data={"name": name, "path": path, "size": size, "true_type": true_type, "sha256": sha,
              "head16": head16(data), "intact": intact, "method": method, "state": "deleted",
              "created_local": created.isoformat() if created else None,
              "modified_local": modified.isoformat() if modified else None,
              "doc": document_meta(data, true_type)},
    )


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
            for e in v.walk():
                if e.is_dir or not e.deleted or e.size == 0 or e.first_cluster < 2:
                    continue
                data = v.read_data(e.first_cluster, e.size, True)
                if not data:
                    continue
                abs_off = vol.offset + v.cluster_offset(e.first_cluster)
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
                visible = s.visible_names()
                for f in s.files:
                    if f.file_type == 5 and f.extents:
                        off = vol.offset + (s.partition_start + f.extents[0][0]) * udf.SECTOR
                        if any(n.name in visible and not n.deleted_flag for n in f.names):
                            taken.append((off, off + f.size))      # still listed: not a recovery
                        else:
                            udf_by_offset[off] = f
                hidden = s.hidden_names()
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
            for c in carve(fh, vol.offset, end, skip=live_ranges):
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
                                       offset=c.offset, length=c.size, sha256=c.sha256, extracted_to=str(target))],
                    confidence=0.9 if c.complete else 0.5, severity=2, tags=["recovered", "carved"],
                    data={"name": disc_name or name, "named": bool(disc_name), "size": c.size,
                          "true_type": c.type, "sha256": c.sha256,
                          "head16": head16(data), "intact": c.complete, "method": "carving",
                          "state": "carved", "doc": meta},
                ))
            log(f"{image.label}: carved {len(findings) - n0} more files with no directory entry")
    return findings
