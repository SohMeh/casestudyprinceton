"""Wiper agent: flag attempts to destroy evidence.

- Media: a volume whose file table is empty while old directories and file
  content still sit in the data area was quick-formatted.
- Computer: traces of wiping and cleaning tools (downloads, installs, runs)
  and the rename-then-delete pattern secure erasers leave in the NTFS journal.
"""
from __future__ import annotations

from typing import Callable, Optional

from .. import fat32
from ..images import SubStream, find_volumes, open_image
from ..ledger import Case, CaseStore, ImageRef
from ..magic import sniff
from ..models import Entity, Evidence, Finding, device_entity

AGENT = "wiper"
Log = Callable[[str], None]

# name fragment -> (display name, what it does)
TOOLS = {
    "eraser": ("Eraser", "secure file eraser that overwrites files before deleting them"),
    "ccleaner": ("CCleaner", "cleaner that removes browser history, recent-file lists and free-space remnants"),
    "ccsetup": ("CCleaner installer", "installer for the CCleaner cleaning tool"),
    "bleachbit": ("BleachBit", "cleaner and file shredder"),
    "sdelete": ("SDelete", "command-line secure delete tool"),
    "privazer": ("PrivaZer", "trace cleaner"),
    "fileshredder": ("File Shredder", "secure file eraser"),
    "shredder": ("file shredder", "secure file eraser"),
    "dban": ("DBAN", "disk wiping tool"),
    "killdisk": ("KillDisk", "disk wiping tool"),
    "wipefile": ("WipeFile", "secure file eraser"),
    "timestomp": ("timestomp", "tool that falsifies file timestamps"),
    "evidence eliminator": ("Evidence Eliminator", "trace cleaner"),
    "anti-forensic": ("anti-forensics", "search for ways to defeat forensic analysis"),
    "antiforensic": ("anti-forensics", "search for ways to defeat forensic analysis"),
}


def tool_match(text: str) -> Optional[tuple[str, str, str]]:
    low = (text or "").lower()
    for frag, (name, what) in TOOLS.items():
        if frag in low:
            return frag, name, what
    return None


def _format_check(case: Case, image: ImageRef, fh, vol, log: Log) -> list[Finding]:
    v = fat32.Fat32Volume(SubStream(fh, vol.offset, vol.size))
    used = v.fat_allocated_clusters()
    live = [e for e in v.walk_live()]
    live_dirs = {e.start_cluster for e in live if e.is_dir}
    orphans = [d for d in v.scan_orphan_directories() if d.cluster not in live_dirs]
    # Count only entries whose content is still where the entry says. Entries left over from an even
    # older format of the medium point elsewhere and say nothing about this format.
    lost_files = [e for e in v.iter_recoverable(orphans) if sniff(v.read_file(e)) not in ("UNKNOWN", "EMPTY")]
    if not orphans or not lost_files:
        log(f"{image.label}: no sign of a format")
        return []
    label = v.volume_label_entry()
    last_write = max([e.created for e in lost_files if e.created] + [d.created for d in orphans if d.created],
                     default=None)
    when = label.modified if label and label.modified else None
    if when and last_write and when < last_write:
        when = None                                   # label predates the files: not the format time
    precise = when is not None
    dev = device_entity(image.id, image.label)
    lost_bytes = sum(e.size for e in lost_files)
    summary = (f"{image.label} was quick-formatted. The file table lists {used} used clusters and {len(live)} live "
               f"entries, yet {len(orphans)} old folders and {len(lost_files)} files "
               f"({lost_bytes / 1048576:.1f} MB) still sit in the data area. ")
    if precise:
        summary += f"The new volume label was written at {when:%Y-%m-%d %H:%M:%S} local time, which dates the format."
    elif last_write:
        summary += f"The format happened after {last_write:%Y-%m-%d %H:%M:%S} local time, the last write before it."
    evidence = [
        Evidence(image=image.name, source="FAT32 file allocation table", offset=vol.offset + v.bpb.fat_offset,
                 length=v.bpb.fat_size * v.bpb.bytes_per_sector, detail=f"{used} clusters marked in use"),
        Evidence(image=image.name, source="orphaned directory clusters in unallocated space",
                 offset=vol.offset + v.bpb.cluster_offset(orphans[0].cluster),
                 detail="clusters " + ", ".join(str(d.cluster) for d in orphans[:12])),
    ]
    if label:
        evidence.append(Evidence(image=image.name, source="root directory volume label entry",
                                 offset=vol.offset + label.entry_offset, length=32,
                                 detail=f"label {label.name!r}, written {label.modified}"))
    log(f"{image.label}: quick format detected, {len(lost_files)} files were left behind")
    return [Finding(
        kind="volume_formatted", agent=AGENT, title=f"{image.label} was quick-formatted",
        summary=summary,
        time=case.local_to_iso(when or last_write),
        time_source=("volume label write time" if precise else "lower bound: last file written before the format"),
        entities=[dev], evidence=evidence, confidence=0.95 if precise else 0.8, severity=3,
        tags=["format", "anti-forensics"] + ([] if precise else ["time-lower-bound"]),
        data={"fat_used_clusters": used, "live_entries": len(live), "orphan_dirs": len(orphans),
              "files_left_behind": len(lost_files), "bytes_left_behind": lost_bytes, "time_precise": precise},
    )]


def _from_ledger(case: Case, store: CaseStore, image: ImageRef, log: Log) -> list[Finding]:
    """Turn the activity agent's raw program and web records into wiping-tool findings."""
    out: list[Finding] = []
    seen = set()
    for f in store.load_findings(case.id):
        if f.get("agent") != "activity" or f.get("data", {}).get("image_id") != image.id:
            continue
        if f["kind"] not in ("program_executed", "program_installed", "program_uninstalled",
                             "web_download", "web_search", "web_visit", "file_opened"):
            continue
        text = " ".join([f["title"], f.get("summary", ""), str(f["data"].get("name", "")),
                         str(f["data"].get("url", "")), str(f["data"].get("query", ""))])
        m = tool_match(text)
        if not m:
            continue
        frag, name, what = m
        verb = {"program_executed": "was run", "program_installed": "was installed",
                "program_uninstalled": "was uninstalled", "web_download": "was downloaded",
                "web_search": "was searched for", "web_visit": "site was visited",
                "file_opened": "was opened"}[f["kind"]]
        key = (frag, f["kind"], f.get("time"))
        if key in seen:
            continue
        seen.add(key)
        out.append(Finding(
            kind="wiping_tool", agent=AGENT, title=f"{name} {verb}",
            summary=f"{name} is a {what}. {f.get('summary', '')}".strip(),
            time=f.get("time"), time_source=f.get("time_source"),
            entities=[Entity(**e) for e in f["entities"]] + [Entity("program", f"program:{frag}", name)],
            evidence=[Evidence(**e) for e in f["evidence"]],
            confidence=min(0.95, f.get("confidence", 0.8)),
            severity=3 if f["kind"] in ("program_executed", "program_installed") else 2,
            tags=["anti-forensics", frag, f["kind"]],
            data={"tool": name, "action": f["kind"], "based_on": f["id"]},
        ))
    wiped = [f for f in store.load_findings(case.id)
             if f["kind"] == "file_wiped" and f.get("data", {}).get("image_id") == image.id]
    log(f"{image.label}: {len(out)} wiping-tool traces" + (f", {len(wiped)} files show an overwrite pattern" if wiped else ""))
    return out


def run(case: Case, store: CaseStore, image: ImageRef, log: Log = print) -> list[Finding]:
    if image.kind in ("computer", "triage"):
        return _from_ledger(case, store, image, log)
    findings: list[Finding] = []
    fh = open_image(image.path)
    for vol in find_volumes(fh):
        if vol.fstype == "FAT32":
            try:
                findings += _format_check(case, image, fh, vol, log)
            except Exception as exc:
                log(f"{image.label}: format check failed ({exc})")
        else:
            log(f"{image.label}: {vol.fstype} volume, no format check for this file system")
    return findings
