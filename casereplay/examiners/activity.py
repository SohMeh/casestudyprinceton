"""Activity agent: rebuild what the user did on the computer, with times.

Reads Windows artifacts straight from the disk image with dissect (pure
Python, read-only): USB history, browser searches and downloads, program
runs, installs, the Recycle Bin, shortcut files and the NTFS change journal.

Every record becomes a finding with the artifact it came from. Noise is
dropped by rule, and the count of dropped records is logged so nothing is
hidden silently.

A second input, a triage export (JSON lines), covers cases where only an
artifact export is available instead of a full disk image.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path, PureWindowsPath
from typing import Any, Callable, Iterable, Optional
from urllib.parse import parse_qs, unquote_plus, urlparse

from ..ledger import Case, CaseStore, ImageRef
from ..magic import EXT_EXPECT, extension_of
from ..models import Entity, Evidence, Finding, device_entity, to_iso
from .wipers import tool_match

AGENT = "activity"
Log = Callable[[str], None]

OFFICE_EXT = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf"}
CLOUD = {"drive.google": "Google Drive", "googledrive": "Google Drive", "icloud": "iCloud",
         "dropbox": "Dropbox", "onedrive": "OneDrive", "skydrive": "OneDrive", "mega.nz": "MEGA",
         "box.com": "Box"}
SEARCH_HOSTS = ("google.", "bing.com", "duckduckgo.com", "yahoo.", "ask.com", "baidu.com")
INTERESTING_VISIT = ("leak", "dlp", "forensic", "eraser", "ccleaner", "wipe", "shred", "delete", "recover",
                     "steganograph", "security checkpoint", "cd-r", "e-mail investigation", "cloud storage")
BURNERS = ("imgburn", "cdburnerxp", "nero", "burn", "isoburn")
NOISE_PROGRAMS = ("svchost", "dllhost", "conhost", "taskhost", "wmiprvse", "searchprotocolhost",
                  "searchfilterhost", "rundll32", "consent", "audiodg", "mscorsvw", "ngen", "wuauclt",
                  "trustedinstaller", "tiworker", "sppsvc", "msiexec", "logonui", "csrss", "lsass", "smss",
                  "wininit", "winlogon", "services", "spoolsv", "dwm", "taskeng", "userinit", "wermgr",
                  "werfault", "defrag", "slui", "verclsid", "makecab", "ielowutil", "wmiadap", "vssvc",
                  "sdclt", "unregmp2", "regsvr32", "mobsync", "oobe", "poqexec", "drvinst", "cmd", "net1")


def _s(value: Any) -> str:
    return "" if value is None else str(value)


def _get(rec: Any, *names: str, default: Any = None) -> Any:
    for n in names:
        try:
            v = getattr(rec, n)
        except Exception:
            continue
        if v not in (None, "", []):
            return v
    return default


def _name(path: str) -> str:
    return PureWindowsPath(path.replace("/", "\\")).name if path else ""


def search_query(url: str) -> Optional[tuple[str, str]]:
    """Return (engine, query) when the URL is a search-engine result page."""
    try:
        u = urlparse(url)
    except Exception:
        return None
    host = u.netloc.lower()
    if not any(h in host for h in SEARCH_HOSTS):
        return None
    qs = parse_qs(u.query) or {}
    frag = parse_qs(u.fragment) or {}
    for key in ("q", "p", "wd", "query"):
        for src in (frag, qs):
            if src.get(key):
                q = unquote_plus(src[key][0]).strip()
                if q:
                    engine = host.replace("www.", "").split(".")[0].capitalize()
                    return engine, q
    return None


class _Collector:
    def __init__(self, case: Case, image: ImageRef, log: Log):
        self.case, self.image, self.log = case, image, log
        self.findings: list[Finding] = []
        self.pc = device_entity(image.id, image.label)
        self.dropped: dict[str, int] = defaultdict(int)

    def add(self, kind: str, title: str, summary: str, time: Optional[str], time_source: str, source: str, *,
            path: Optional[str] = None, detail: Optional[str] = None, severity: int = 1,
            confidence: float = 0.9, tags: Iterable[str] = (), data: Optional[dict] = None,
            entities: Iterable[Entity] = (), time_end: Optional[str] = None) -> Finding:
        f = Finding(
            kind=kind, agent=AGENT, title=title[:160], summary=summary, time=time, time_end=time_end,
            time_source=time_source, entities=[self.pc, *entities],
            evidence=[Evidence(image=self.image.name, source=source, path=path, detail=(detail or None))],
            confidence=confidence, severity=severity, tags=list(tags), data=data or {},
        )
        self.findings.append(f)
        return f


def _section(c: _Collector, name: str, fn: Callable[[], Optional[int]]) -> None:
    try:
        n = fn()
        c.log(f"{c.image.label}: {name}: {n if n is not None else 'done'}")
    except Exception as exc:
        c.log(f"{c.image.label}: {name}: skipped ({type(exc).__name__}: {str(exc)[:120]})")


def _usb_device_entity(case: Case, store: CaseStore, label: str, serial: str) -> Entity:
    """Tie a USB registry record to an image in the case.

    Uses the volume label the intake agent read from each image, or a serial
    the investigator typed into the image notes (from the seizure record).
    """
    labels = {}
    for f in store.load_findings(case.id):
        if f["kind"] == "system_info" and f.get("data", {}).get("label"):
            labels[f["data"].get("image_id")] = f["data"]["label"].lower()
    for im in case.images:
        if serial and serial.lower() in im.notes.lower():
            return device_entity(im.id, im.label)
        vol = labels.get(im.id)
        if vol and label and (vol in label.lower() or label.lower() in vol):
            return device_entity(im.id, im.label)
    key = serial or label or "unknown"
    return Entity("device", f"device:usb:{key}", f"USB device {label or serial}")


# -- full disk image ---------------------------------------------------------

def _run_target(case: Case, store: CaseStore, image: ImageRef, log: Log) -> list[Finding]:
    from dissect.target import Target

    c = _Collector(case, image, log)
    log(f"{image.label}: opening disk image (read-only)")
    t = Target.open(image.path)

    def system() -> int:
        host = _s(getattr(t, "hostname", ""))
        version = _s(getattr(t, "version", ""))
        installed = None
        try:
            installed = t.install_date
        except Exception:
            pass
        c.add("system_info", f"Computer {host or image.label}: {version or 'Windows'}",
              f"Host name {host}. Operating system {version}."
              + (f" Installed {to_iso(installed)}." if installed else ""),
              to_iso(installed) if installed else None, "Windows install date (registry)",
              "SOFTWARE registry hive", path="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
              tags=["system"], data={"hostname": host, "version": version})
        n = 1
        for u in t.users():
            nm = _s(_get(u, "name"))
            if nm:
                c.add("system_info", f"User account {nm}", f"Account {nm}, home {_s(_get(u, 'home'))}.",
                      None, "", "SAM / ProfileList registry", detail=_s(_get(u, "sid")), tags=["account"],
                      entities=[Entity("account", f"account:{nm.lower()}", nm)], data={"account": nm})
                n += 1
        return n

    def usb() -> int:
        n = 0
        for r in t.usb():
            serial = _s(_get(r, "serial"))
            label = _s(_get(r, "friendly_name", "product"))
            vols = [_s(v) for v in (_get(r, "volumes", default=[]) or [])]
            dev = _usb_device_entity(case, store, " ".join(vols) or label, serial)
            base = {"serial": serial, "friendly_name": label, "vendor": _s(_get(r, "vendor")),
                    "product": _s(_get(r, "product")), "volumes": vols,
                    "mounts": [_s(m) for m in (_get(r, "mounts", default=[]) or [])]}
            for field, what in (("first_insert", "first connected"), ("last_insert", "connected (most recent)"),
                                ("last_removal", "removed (most recent)")):
                ts = _get(r, field)
                if not ts:
                    continue
                c.add("usb_connected", f"USB device {label or serial} {what}",
                      f"{label} (serial {serial}) was {what}. Volume names: {', '.join(vols) or 'not recorded'}.",
                      to_iso(ts), f"USBSTOR registry: {field}", "SYSTEM registry hive: USBSTOR",
                      path=_s(_get(r, "source")), detail=f"serial {serial}", severity=2,
                      tags=["usb", field], entities=[dev], data={**base, "event": field})
                n += 1
        return n

    def browser() -> int:
        n = 0
        seen = set()
        for r in t.browser.history():
            url = _s(_get(r, "url"))
            ts = _get(r, "ts")
            if not url or not ts:
                continue
            who = _s(_get(r, "browser"))
            sq = search_query(url)
            low = (url + " " + _s(_get(r, "title"))).lower()
            if sq:
                engine, q = sq
                key = (q.lower(), to_iso(ts)[:16])
                if key in seen:
                    continue
                seen.add(key)
                hot = tool_match(q) or any(k in q.lower() for k in INTERESTING_VISIT)
                c.add("web_search", f'Searched {engine} for "{q}"',
                      f'The user searched {engine} for "{q}" in {who or "a browser"}.',
                      to_iso(ts), "browser history visit time", f"{who} history database",
                      path=_s(_get(r, "source")), detail=url[:300], severity=3 if hot else 2,
                      tags=["search", who], data={"query": q, "engine": engine, "url": url, "browser": who})
                n += 1
            elif any(k in low for k in CLOUD) or tool_match(low) or any(k in low for k in INTERESTING_VISIT):
                key = (urlparse(url).netloc + urlparse(url).path, to_iso(ts)[:16])
                if key in seen:
                    continue
                seen.add(key)
                cloud = next((v for k, v in CLOUD.items() if k in low), None)
                c.add("cloud_activity" if cloud else "web_visit",
                      f"Visited {cloud or urlparse(url).netloc}",
                      f"{_s(_get(r, 'title')) or url[:120]} was opened in {who or 'a browser'}.",
                      to_iso(ts), "browser history visit time", f"{who} history database",
                      path=_s(_get(r, "source")), detail=url[:300], severity=2,
                      tags=["visit", who] + (["cloud"] if cloud else []),
                      data={"url": url, "title": _s(_get(r, "title")), "browser": who, "service": cloud})
                n += 1
            else:
                c.dropped["ordinary web visits"] += 1
        return n

    def downloads() -> int:
        n = 0
        for r in t.browser.downloads():
            ts = _get(r, "ts_start", "ts_end", "ts")
            url = _s(_get(r, "url"))
            path = _s(_get(r, "path"))
            nm = _name(path) or url.rsplit("/", 1)[-1]
            c.add("web_download", f"Downloaded {nm}", f"{nm} was downloaded from {url[:160]}.",
                  to_iso(ts) if ts else None, "browser download start time",
                  f"{_s(_get(r, 'browser'))} download history", path=path, detail=url[:300], severity=2,
                  tags=["download"], data={"name": nm, "url": url, "path": path})
            n += 1
        return n

    def prefetch() -> int:
        n = 0
        try:
            recs = t.prefetch(compact=True)
        except TypeError:
            recs = t.prefetch()
        seen = set()
        for r in recs:
            exe = _name(_s(_get(r, "filename")))
            times = [_get(r, "ts")] + list(_get(r, "previousruns", default=[]) or [])
            low = exe.lower()
            stem = low.rsplit(".", 1)[0]
            if stem in NOISE_PROGRAMS:
                c.dropped["operating-system program runs"] += len([x for x in times if x])
                continue
            hot = tool_match(low)
            cloud = next((v for k, v in CLOUD.items() if k in low), None)
            for ts in times:
                if not ts or (low, to_iso(ts)) in seen:
                    continue
                seen.add((low, to_iso(ts)))
                c.add("program_executed", f"Ran {exe}",
                      f"{exe} was started (run count {_s(_get(r, 'runcount'))}).",
                      to_iso(ts), "Prefetch last-run time", "Windows Prefetch",
                      path=_s(_get(r, "prefetch")), severity=3 if hot else (2 if cloud or any(b in low for b in BURNERS) else 1),
                      tags=["prefetch"] + (["cloud"] if cloud else []),
                      entities=[Entity("program", f"program:{stem}", exe)],
                      data={"name": exe, "runcount": _get(r, "runcount")})
                n += 1
        return n

    def userassist() -> int:
        n = 0
        for r in t.userassist():
            ts = _get(r, "ts")
            p = _s(_get(r, "path"))
            if not ts or not p or to_iso(ts).startswith(("1601", "1970")):
                continue
            exe = _name(p) or p
            c.add("program_executed", f"Started {exe} from the desktop shell",
                  f"{exe} was launched through Explorer by the logged-in user.",
                  to_iso(ts), "UserAssist last-run time", "NTUSER.DAT: UserAssist", path=p,
                  severity=3 if tool_match(p) else 1, tags=["userassist"],
                  entities=[Entity("program", f"program:{exe.lower().rsplit('.', 1)[0]}", exe)],
                  data={"name": exe, "count": _get(r, "number_of_executions")})
            n += 1
        return n

    def applications() -> int:
        n = 0
        for r in t.applications():
            nm = _s(_get(r, "name"))
            ts = _get(r, "ts_installed", "ts_modified", "ts")
            if not nm:
                continue
            hot = tool_match(nm)
            cloud = next((v for k, v in CLOUD.items() if k in nm.lower().replace(" ", "")), None)
            if not ts:
                c.dropped["installed programs without an install time"] += 1
                continue
            c.add("program_installed", f"Installed {nm}", f"{nm} {_s(_get(r, 'version'))} was installed.",
                  to_iso(ts), "Uninstall registry key time", "SOFTWARE registry hive: Uninstall",
                  path=_s(_get(r, "path")), severity=3 if hot else (2 if cloud else 1),
                  tags=["install"] + (["cloud"] if cloud else []),
                  entities=[Entity("program", f"program:{nm.lower()}", nm)],
                  data={"name": nm, "version": _s(_get(r, "version"))})
            n += 1
        return n

    def recyclebin() -> int:
        n = 0
        for r in t.recyclebin():
            ts = _get(r, "ts")
            orig = _s(_get(r, "path"))
            nm = _name(orig)
            c.add("recycle_bin", f"Deleted {nm} to the Recycle Bin",
                  f"{orig} ({_s(_get(r, 'filesize'))} bytes) was sent to the Recycle Bin.",
                  to_iso(ts) if ts else None, "Recycle Bin $I record deletion time", "Recycle Bin $I file",
                  path=_s(_get(r, "deleted_path", "source")), detail=orig, severity=2, tags=["deleted"],
                  data={"name": nm, "original_path": orig, "size": _get(r, "filesize")})
            n += 1
        return n

    def lnk() -> int:
        n = 0
        seen = set()
        for r in t.lnk():
            target = _s(_get(r, "lnk_full_path", "local_base_path", "lnk_net_name", "lnk_relativepath"))
            ts = _get(r, "lnk_mtime", "lnk_ctime")
            if not target or not ts:
                continue
            nm = _name(target)
            ext = extension_of(nm)
            removable = not target.upper().startswith(("C:", "%"))
            if ext not in OFFICE_EXT and not removable and ext not in EXT_EXPECT:
                c.dropped["shortcuts to ordinary items"] += 1
                continue
            key = (target.lower(), to_iso(ts))
            if key in seen:
                continue
            seen.add(key)
            c.add("file_opened", f"Opened {nm or target}",
                  f"{target} was opened. Windows recorded a shortcut to it.",
                  to_iso(ts), "shortcut (LNK) modification time: last time the file was opened",
                  "Windows shortcut file", path=_s(_get(r, "lnk_path")), detail=target,
                  severity=2 if (removable or ext in OFFICE_EXT) else 1,
                  tags=["lnk"] + (["external-volume"] if removable else []),
                  data={"name": nm, "target": target, "volume": target[:2] if ":" in target[:3] else "network"})
            n += 1
        return n

    def usn_records():
        """Yield (segment, time, reason, name, full_path_getter) for rename and delete records.

        Reads the journal directly and resolves a full path only when asked,
        which is far faster than resolving every record.
        """
        try:
            from dissect.ntfs.util import segment_reference
            seen_fs = False
            for fs in t.filesystems:
                if getattr(fs, "__type__", "") != "ntfs" or not getattr(fs.ntfs, "usnjrnl", None):
                    continue
                seen_fs = True
                for rec in fs.ntfs.usnjrnl.records():
                    reason = str(rec.Reason).upper()
                    usn_total[0] += 1
                    if "RENAME" not in reason and "FILE_DELETE" not in reason:
                        continue
                    try:
                        ts = rec.timestamp
                    except Exception:
                        continue
                    ref = rec.record.FileReferenceNumber
                    seg = f"{segment_reference(ref)}#{ref.SequenceNumber}"
                    yield seg, ts, reason, rec.filename or "", (lambda r=rec: _s(r.full_path))
            if seen_fs:
                return
        except Exception as exc:
            c.log(f"{image.label}: direct journal read failed ({exc}), using the slower reader")
        for r in t.usnjrnl():
            usn_total[0] += 1
            reason = _s(_get(r, "reason")).upper()
            ts = _get(r, "ts")
            if not ts or ("RENAME" not in reason and "FILE_DELETE" not in reason):
                continue
            path = _s(_get(r, "path"))
            yield _s(_get(r, "segment_id")), ts, reason, _name(path), (lambda p=path: p)

    usn_total = [0]

    def usn() -> int:
        """Renames that change the extension, and the overwrite pattern of secure erasers."""
        n = 0
        pending: dict[str, tuple[str, Any]] = {}
        renames: dict[str, list[tuple[Any, str, str, Any]]] = defaultdict(list)   # ts, old, new, path getter
        deleted_at: dict[str, Any] = {}
        for seg, ts, reason, name, get_path in usn_records():
            if "RENAME_OLD_NAME" in reason:
                pending[seg] = (name, get_path)
            elif "RENAME_NEW_NAME" in reason and seg in pending:
                old, old_path = pending.pop(seg)
                renames[seg].append((ts, old, name, get_path, old_path))
            elif "FILE_DELETE" in reason:
                deleted_at[seg] = ts
        for seg, items in renames.items():
            first_old = items[0][1]
            span = items[-1][0] - items[0][0]
            dele = deleted_at.get(seg)
            if len(items) >= 3 and span <= timedelta(minutes=3) and dele and dele - items[-1][0] <= timedelta(minutes=3):
                where = items[0][4]().replace("/", "\\")
                c.add("file_wiped", f"{first_old} was overwritten and deleted",
                      f"{where or first_old} was renamed {len(items)} times to meaningless names within "
                      f"{int(span.total_seconds())} seconds and then deleted. Secure erasers do this to hide "
                      "the file name after overwriting the content.",
                      to_iso(items[0][0]), "NTFS change journal record time", "$UsnJrnl:$J",
                      path=where or first_old, detail=" > ".join(x[2] for x in items[:8]),
                      severity=3, tags=["wiped", "anti-forensics"], time_end=to_iso(dele),
                      data={"name": first_old, "path": where, "renames": len(items)})
                n += 1
                continue
            for ts, old, new, get_path, _ in items:
                eo, en = extension_of(old), extension_of(new)
                if eo == en or not (eo in OFFICE_EXT or en in OFFICE_EXT):
                    c.dropped["ordinary renames"] += 1
                    continue
                where = get_path().replace("/", "\\")
                c.add("file_renamed", f"Renamed {old} to {new}",
                      f"{old} was renamed to {new} in {where.rsplit(chr(92), 1)[0] or 'its folder'}. "
                      f"The extension changed from .{eo or '(none)'} to .{en or '(none)'}.",
                      to_iso(ts), "NTFS change journal record time", "$UsnJrnl:$J", path=where, detail=f"was {old}",
                      severity=3 if eo in OFFICE_EXT else 2, tags=["rename", "extension-change"],
                      data={"old_name": old, "new_name": new, "new_path": where, "name": new})
                n += 1
        c.log(f"{image.label}: change journal: read {usn_total[0]} records")
        return n

    _section(c, "system and accounts", system)
    _section(c, "USB history", usb)
    _section(c, "browser history", browser)
    _section(c, "browser downloads", downloads)
    _section(c, "program runs (Prefetch)", prefetch)
    _section(c, "program runs (UserAssist)", userassist)
    _section(c, "installed programs", applications)
    _section(c, "Recycle Bin", recyclebin)
    _section(c, "opened files (shortcuts)", lnk)
    _section(c, "renames and wipes (change journal)", usn)
    for what, count in sorted(c.dropped.items()):
        log(f"{image.label}: left out {count} {what}")
    return c.findings


# -- triage export -----------------------------------------------------------

def _run_triage(case: Case, store: CaseStore, image: ImageRef, log: Log) -> list[Finding]:
    """One JSON object per line: {time, kind, title, summary, source, path, detail, severity, data}."""
    c = _Collector(case, image, log)
    n = 0
    for line in Path(image.path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        r = json.loads(line)
        when = r.get("time")
        if when and not re.search(r"(Z|[+-]\d\d:?\d\d)$", when):
            when = case.local_to_iso(datetime.fromisoformat(when))
        ents = []
        if r.get("device"):
            im = case.image(r["device"])
            ents.append(device_entity(r["device"], im.label if im else r["device"]))
        if r.get("program"):
            ents.append(Entity("program", f"program:{r['program'].lower()}", r["program"]))
        c.add(r["kind"], r["title"], r.get("summary", ""), when, r.get("time_source", "artifact record time"),
              r.get("source", "triage export"), path=r.get("path"), detail=r.get("detail"),
              severity=int(r.get("severity", 1)), tags=r.get("tags", []), data=r.get("data", {}), entities=ents)
        n += 1
    log(f"{image.label}: read {n} artifact records from the triage export")
    return c.findings


def run(case: Case, store: CaseStore, image: ImageRef, log: Log = print) -> list[Finding]:
    if image.kind == "triage":
        return _run_triage(case, store, image, log)
    if image.kind != "computer":
        log(f"{image.label}: not a computer image, nothing for the activity agent")
        return []
    return _run_target(case, store, image, log)
