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
import html as htmllib
from datetime import datetime, timedelta, timezone
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
HOT_SEARCH = ("leak", "confidential", "dlp", "drm", "forensic", "investigation", "artifact", "event log",
              "cd burning", "external device", "anti-forensic", "antiforensic", "eraser", "ccleaner", "wipe",
              "shred", "secure delete", "cloud", "google drive", "icloud", "tethering", "file sharing",
              "security checkpoint", "steganograph", "without being", "monitor usb", "hide")
UNINSTALLERS = ("uninst", "unins000", "unins001", "uninstall", "uninstaller")
DRIVE_KIND = {2: "removable drive", 3: "fixed disk", 4: "network drive", 5: "CD or DVD drive"}
NOISE_PROGRAMS = ("svchost", "dllhost", "conhost", "taskhost", "wmiprvse", "searchprotocolhost",
                  "searchfilterhost", "rundll32", "consent", "audiodg", "mscorsvw", "ngen", "wuauclt",
                  "trustedinstaller", "tiworker", "sppsvc", "msiexec", "logonui", "csrss", "lsass", "smss",
                  "wininit", "winlogon", "services", "spoolsv", "dwm", "taskeng", "userinit", "wermgr",
                  "werfault", "defrag", "slui", "verclsid", "makecab", "ielowutil", "wmiadap", "vssvc",
                  "sdclt", "unregmp2", "regsvr32", "mobsync", "oobe", "poqexec", "drvinst", "cmd", "net1")


_t = datetime.fromisoformat


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


def _html_text(raw: Any) -> str:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    text = re.sub(r"(?is)<(style|script).*?</\1>|<[^>]+>", " ", raw or "")
    return re.sub(r"\s+", " ", htmllib.unescape(text)).strip()


def _b(value: Any) -> str:
    """Text from the bytes or little structs that link files use for strings."""
    for _ in range(3):
        if isinstance(value, bytes):
            return value.split(b"\x00")[0].decode("cp1252", "replace")
        if isinstance(value, str) or value is None:
            return value or ""
        inner = [getattr(value, a) for a in ("net_name", "device_name", "volume_label") if hasattr(value, a)]
        value = inner[0] if inner else None
    return ""


def _image_volumes(case: Case, store: CaseStore) -> dict[str, dict]:
    """Volume label and serial number of every image, as read by the intake agent."""
    out: dict[str, dict] = {}
    for f in store.load_findings(case.id):
        d = f.get("data", {})
        if f["kind"] == "system_info" and (d.get("label") or d.get("volume_serial")):
            out[d.get("image_id")] = {"label": (d.get("label") or "").lower(), "vsn": d.get("volume_serial")}
    return out


# -- full disk image ---------------------------------------------------------

def _run_target(case: Case, store: CaseStore, image: ImageRef, log: Log) -> list[Finding]:
    from dissect.target import Target

    c = _Collector(case, image, log)
    log(f"{image.label}: opening disk image (read-only)")
    t = Target.open(image.path)
    volumes = _image_volumes(case, store)

    def image_device(label: str = "", vsn: Optional[int] = None) -> Optional[Entity]:
        """The evidence image a volume on this computer corresponds to, by serial number or label."""
        for im in case.images:
            v = volumes.get(im.id)
            if v and ((vsn and v["vsn"] == vsn) or (label and v["label"] == label.lower())):
                return device_entity(im.id, im.label)
        return None

    def case_time(dt) -> str:
        return dt.astimezone(case.tz).strftime("%Y-%m-%d %H:%M:%S")

    def homes() -> list:
        out = []
        for u in t.users():
            home = _s(_get(u, "home"))
            if "\\users\\" in home.lower():
                for cand in (home, "sysvol/Users/" + home.rsplit("\\", 1)[-1]):
                    try:
                        path = t.fs.path(cand)
                        if path.exists():
                            out.append((_s(_get(u, "name")), path))
                            break
                    except Exception:
                        continue
        return out

    def reg_keys(path: str) -> list:
        try:
            return list(t.registry.keys(path))
        except Exception:
            return []

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
        """USB storage history from the registry, the driver install log and the volume cache."""
        n = 0
        devices: dict[str, dict] = {}
        for r in t.usb():
            serial = _s(_get(r, "serial")).split("&")[0]
            if serial:
                devices.setdefault(serial, {"name": _s(_get(r, "friendly_name", "product")) or "USB storage device",
                                            "first": set(), "last": set(), "path": ""})
        for root in ("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB"):
            for key in reg_keys(root):
                for dev in key.subkeys():
                    for ser in dev.subkeys():
                        d = devices.get(ser.name.split("&")[0])
                        if d is None:
                            continue
                        d["last"].add(ser.ts)
                        d["path"] = d["path"] or f"{root}\\{dev.name}\\{ser.name}"
                        for sub in ser.subkeys():
                            if sub.name == "LogConf":
                                d["first"].add(sub.ts)
        try:                                              # first driver install, written in local time
            lines = t.fs.path("sysvol/windows/inf/setupapi.dev.log").read_text(errors="replace").splitlines()
            for i, line in enumerate(lines[:-1]):
                m = re.search(r"Device Install \(Hardware initiated\) - USBSTOR\\[^\\]+\\([^\]&]+)", line)
                tm = m and re.search(r"Section start (\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d)", lines[i + 1])
                if tm and m.group(1) in devices:
                    devices[m.group(1)]["setupapi"] = datetime(*map(int, tm.groups()))
        except Exception:
            pass
        # Volumes Windows saw on removable media: label and volume serial number, with the time first seen.
        vols = []
        for key in reg_keys("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt"):
            for sub in key.subkeys():
                m = re.match(r"^(.*)_(\d+)$", sub.name)
                if m:
                    head = m.group(1)
                    label = head.split("__", 1)[1].lstrip("_") if "__" in head else head
                    vols.append({"ts": sub.ts, "label": label, "vsn": int(m.group(2)), "key": sub.name})
        vols = list({(v["label"], v["vsn"]): v for v in sorted(vols, key=lambda v: v["ts"])}.values())

        for serial, d in devices.items():
            first_reg = min(d["first"]) if d["first"] else None
            first = case.local_to_iso(d["setupapi"]) if d.get("setupapi") else to_iso(first_reg)
            src = ("setupapi.dev.log section start (local time), confirmed by the USBSTOR LogConf key time"
                   if d.get("setupapi") and first_reg else
                   "setupapi.dev.log section start (local time)" if d.get("setupapi") else "USBSTOR LogConf key time")
            anchor = first_reg or (_t(first) if first else None)
            near = [v for v in vols if anchor and abs((v["ts"] - anchor).total_seconds()) <= 30]
            label = near[0]["label"] if near else ""
            d["label"] = label
            dev = (image_device(label, near[0]["vsn"]) if near else None) or \
                Entity("device", f"device:usb:{serial}", f"USB device {label or d['name']} ({serial[-4:]})")
            vol_text = f' Windows mounted it as volume "{label}".' if label else ""
            base = {"serial": serial, "friendly_name": d["name"], "volume_label": label,
                    "volume_serial": near[0]["vsn"] if near else None}
            times = []
            if first:
                times.append((first, "first_insert", "connected for the first time", src))
            for ts in sorted(d["last"]):
                iso = to_iso(ts)
                if all(abs((_t(iso) - _t(x[0])).total_seconds()) > 30 for x in times):
                    times.append((iso, "last_insert", "connected again", "USB device registry key last-write time"))
            for iso, event, what, source in times:
                c.add("usb_connected", f"{dev.label} {what}",
                      f"{d['name']} with serial {serial} was {what} on this computer.{vol_text}",
                      iso, source, "SYSTEM registry hive: Enum\\USBSTOR and Enum\\USB", path=d["path"],
                      detail=f"serial {serial}", severity=2, tags=["usb", event], entities=[dev],
                      data={**base, "event": event})
                n += 1
        # The same label coming back with a new serial number means the volume was formatted in between.
        by_label: dict[str, list] = defaultdict(list)
        for v in vols:
            by_label[v["label"]].append(v)
        for label, vs in by_label.items():
            for before, after in zip(vs, vs[1:]):
                if not label or not any(d.get("label") == label for d in devices.values()):
                    continue
                dev = image_device(label, after["vsn"]) or Entity("device", f"device:volume:{label}", f'Volume "{label}"')
                c.add("volume_formatted", f'Volume "{label}" came back with a new serial number',
                      f'Windows first saw the volume "{label}" with serial number {before["vsn"]:08X} and later, at '
                      f'{case_time(after["ts"])} local time, with serial number {after["vsn"]:08X}. A volume only '
                      "gets a new serial number when it is formatted, so it was formatted shortly before that moment.",
                      to_iso(after["ts"]), "registry key time: first time Windows saw the reformatted volume",
                      "SOFTWARE registry hive: EMDMgmt", path="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt",
                      detail=f"{before['key']} then {after['key']}", severity=3, confidence=0.85,
                      tags=["format", "anti-forensics", "seen-from-computer"], entities=[dev],
                      data={"label": label, "old_serial": before["vsn"], "new_serial": after["vsn"]})
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
                hot = tool_match(q) or any(k in q.lower() for k in HOT_SEARCH)
                c.add("web_search", f'Searched {engine} for "{q}"',
                      f'The user searched {engine} for "{q}" in {who or "a browser"}.',
                      to_iso(ts), "browser history visit time", f"{who} history database",
                      path=_s(_get(r, "source")), detail=url[:300], severity=3 if hot else 1,
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
            if stem in UNINSTALLERS:
                linked = [_s(x) for x in (_get(r, "linkedfiles", default=[]) or [])]
                prog = next((m.group(1) for x in linked
                             for m in [re.search(r"\\PROGRAM FILES(?: \(X86\))?\\([^\\]+)\\", x, re.I)] if m), "")
                ts0 = _get(r, "ts")
                if prog and ts0 and ts0.year > 1990:
                    c.add("program_uninstalled", f"Uninstalled {prog.title()}",
                          f"The uninstaller in the {prog.title()} program folder was run, which removes the program.",
                          to_iso(ts0), "Prefetch last-run time of the uninstaller", "Windows Prefetch",
                          path=_s(_get(r, "prefetch")), detail=next((x for x in linked if prog in x), ""),
                          severity=3 if tool_match(prog) else 2, tags=["prefetch", "uninstall"],
                          entities=[Entity("program", f"program:{prog.lower()}", prog.title())],
                          data={"name": prog.title()})
                    n += 1
                    continue
            for ts in times:
                if not ts or ts.year < 1990 or (low, to_iso(ts)) in seen:
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
        seen = set()
        for r in t.applications():
            nm = _s(_get(r, "name"))
            if not nm or _s(_get(r, "type")) == "system" or nm in seen:
                continue
            inst, mod = _get(r, "ts_installed"), _get(r, "ts_modified")
            # The install date is often a bare day. The registry key time on that day is the precise moment.
            ts = mod if (mod and (not inst or (inst.hour, inst.minute, inst.second) == (0, 0, 0))) else inst
            if not ts or ts.year < 1990:
                c.dropped["installed programs without an install time"] += 1
                continue
            seen.add(nm)
            hot = tool_match(nm)
            cloud = next((v for k, v in CLOUD.items() if k in nm.lower().replace(" ", "")), None)
            c.add("program_installed", f"Installed {nm}", f"{nm} {_s(_get(r, 'version'))} was installed.".replace("  ", " "),
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

    def links() -> int:
        """Recently opened files: Windows writes a shortcut the first time, and updates it each time after."""
        try:
            from dissect.shellitem.lnk import Lnk
        except Exception:
            Lnk = None
            c.log(f"{image.label}: dissect.shellitem is not installed, shortcut targets are read from file names only")
        n = 0
        seen = set()
        for user, home in homes():
            for sub in ("AppData/Roaming/Microsoft/Windows/Recent", "AppData/Roaming/Microsoft/Office/Recent"):
                folder = home.joinpath(sub)
                try:
                    files = [f for f in folder.iterdir() if f.name.lower().endswith(".lnk")]
                except Exception:
                    continue
                for f in sorted(files, key=lambda x: x.name.lower()):
                    st = f.stat()
                    born = datetime.fromtimestamp(getattr(st, "st_birthtime", None) or st.st_ctime, timezone.utc)
                    changed = datetime.fromtimestamp(st.st_mtime, timezone.utc)
                    target, kind, vsn, vlabel, share = "", None, None, "", ""
                    if Lnk:
                        try:
                            li = Lnk(f.open()).linkinfo
                            target = _b(getattr(li, "local_base_path", None))
                            net = getattr(li, "common_network_relative_link", None)
                            share = _b(getattr(net, "net_name", None)) if net is not None else ""
                            letter = _b(getattr(net, "device_name", None)) if net is not None else ""
                            if not target and share:
                                target = share + "\\" + _b(getattr(li, "common_path_suffix", None))
                                kind = 4
                                share = f"{share} ({letter})" if letter else share
                            vol = getattr(li, "volumeid", None)
                            if vol is not None and not share:
                                kind = getattr(vol, "drive_type", None)
                                vsn = getattr(vol, "drive_serial_number", None)
                                vlabel = _b(getattr(vol, "volume_label", None))
                        except Exception:
                            pass
                    nm = _name(target) or f.name[:-4]
                    is_folder = "." not in nm[-6:]
                    where = (f"the network share {share}" if share else
                             f"the {DRIVE_KIND.get(kind, 'drive')} {target[:2]}" if target[1:2] == ":" else "an unknown location")
                    external = bool(share) or (target[1:2] == ":" and kind not in (None, 3))
                    dev = image_device(vlabel, vsn) if vsn and kind != 3 else None
                    ext = extension_of(nm)
                    for when, verb, src in ((born, "Opened", "shortcut creation time: first time this item was opened"),
                                            (changed, "Opened again:", "shortcut modification time: most recent time it was opened")):
                        if verb != "Opened" and (changed - born).total_seconds() < 60:
                            continue
                        key = (nm.lower(), to_iso(when)[:16])
                        if key in seen:
                            continue
                        seen.add(key)
                        c.add("file_opened", f"{verb} {nm}",
                              f"{user} opened {target or nm} from {where}."
                              + (f" The volume there had serial number {vsn:08X}." if vsn and external else ""),
                              to_iso(when), src, "Windows shortcut (LNK) in the Recent folder", path=str(f), detail=target,
                              severity=2 if (external or ext in OFFICE_EXT) and not is_folder else 1,
                              tags=["lnk"] + (["external-volume"] if external else []) + (["folder"] if is_folder else []),
                              entities=[dev] if dev else [],
                              data={"name": nm, "target": target, "volume_serial": vsn, "drive_kind": DRIVE_KIND.get(kind),
                                    "share": share, "user": user})
                        n += 1
        return n

    def shellbags() -> int:
        """Folders the user browsed in Explorer on network shares and non-system drives."""
        n = 0
        seen = set()
        for r in t.shellbags():
            raw, ts = _s(_get(r, "path")), _get(r, "regf_mtime")
            if not raw or not ts or "<UNKNOWN" in raw:
                continue
            clean = re.sub(r"<[A-Z_]+ \{\d+\}>\\?", "", raw)
            m = re.match(r"^My Computer\\([A-Z]:\\.+)$", clean)
            if m and m.group(1)[0] != "C":
                loc = m.group(1)
            elif clean.startswith("Network\\") and clean.count("\\") >= 2:
                loc = "\\\\" + clean[len("Network\\"):]
            else:
                c.dropped["folder views on the system drive"] += 1
                continue
            key = (loc.lower(), to_iso(ts)[:16])
            if key in seen:
                continue
            seen.add(key)
            c.add("file_opened", f"Browsed {loc}", f"The folder {loc} was open in Explorer.",
                  to_iso(ts), "shellbag registry key time: when this folder view was last saved",
                  "user registry hive: Shellbags", path=_s(_get(r, "regf_key_path")), detail=raw,
                  severity=2, confidence=0.75, tags=["shellbag", "folder"] + (["network"] if loc.startswith("\\\\") else []),
                  data={"name": loc.rstrip("\\").rsplit("\\", 1)[-1], "target": loc, "folder": True})
            n += 1
        return n

    def gdrive() -> int:
        """Google Drive desktop client: what its sync log says was uploaded, downloaded and deleted."""
        n = 0
        line_re = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d+ ([+-]\d{4}) .*?Worker successfully completed "
                             r"\[ImmutableChange\(Direction\.(\w+), Action\.(\w+)(.*)$")
        for user, home in homes():
            log_path = home.joinpath("AppData/Local/Google/Drive/user_default/sync_log.log")
            try:
                text = log_path.read_text(errors="replace")
            except Exception:
                continue
            sizes = {_name(m.group(1).replace("\\\\", "\\")): int(m.group(2))
                     for m in re.finditer(r"RawEvent\(\w+, path=u'([^']+)'.*?size=(\d+)", text)}
            for line in text.splitlines():
                m = line_re.match(line)
                if not m:
                    continue
                stamp, zone, direction, action, rest = m.groups()
                nm = re.search(r"name=(?:u'([^']+)'|([^,\]]+))", rest)
                name = (nm.group(1) or nm.group(2)).strip() if nm else "an item"
                when = datetime.strptime(f"{stamp} {zone}", "%Y-%m-%d %H:%M:%S %z")
                up = direction == "UPLOAD"
                what = {("UPLOAD", "CREATE"): f"Uploaded {name} to Google Drive",
                        ("UPLOAD", "DELETE"): f"Deleted {name} from Google Drive",
                        ("UPLOAD", "MODIFY"): f"Updated {name} on Google Drive",
                        ("DOWNLOAD", "CREATE"): f"Google Drive synced {name} down to this computer",
                        ("DOWNLOAD", "DELETE"): f"{name} was removed by a change made in the cloud"}.get(
                    (direction, action), f"Google Drive {action.lower()} {name}")
                size = sizes.get(name)
                c.add("cloud_activity", what,
                      f"The Google Drive client of {user} finished this change: {direction.lower()}, {action.lower()}, "
                      f"{name}" + (f" ({size:,} bytes)." if size else "."),
                      to_iso(when), "Google Drive sync log line time (the log records its own UTC offset)",
                      "Google Drive sync_log.log", path=str(log_path), detail=line[:300],
                      severity=3 if up and action in ("CREATE", "DELETE") else 1,
                      tags=["cloud", "google-drive", direction.lower(), action.lower()],
                      entities=[Entity("program", "program:googledrive", "Google Drive")],
                      data={"service": "Google Drive", "name": name, "direction": direction, "action": action, "size": size})
                n += 1
        return n

    def mail() -> int:
        """Outlook mailboxes, read with libpff when it is installed."""
        boxes = []
        for user, home in homes():
            for sub in ("AppData/Local/Microsoft/Outlook", "Documents/Outlook Files"):
                try:
                    boxes += [(user, f) for f in home.joinpath(sub).iterdir() if f.name.lower().endswith((".ost", ".pst"))]
                except Exception:
                    continue
        if not boxes:
            return 0
        try:
            import pypff
        except Exception:
            c.log(f"{image.label}: {len(boxes)} Outlook mailbox found, but libpff-python is not installed, so email "
                  "was not read (pip install libpff-python)")
            return 0
        n = 0
        for user, box in boxes:
            owner = box.name.split("@")[0].split(".")[0].lower()
            pff = pypff.file()
            pff.open_file_object(box.open())

            def walk(folder, name: str) -> None:
                nonlocal n
                for i in range(folder.number_of_sub_messages):
                    try:
                        m = folder.get_sub_message(i)
                        subject = (m.subject or "").strip()
                        sender = (m.sender_name or "").strip()
                        if "Sync Issues" in name or subject.startswith("Synchronization Log"):
                            continue
                        body = _html_text(m.html_body) if m.html_body else _html_text(m.plain_text_body or b"")
                        own = body.split(" From: ")[0].split("-----Original Message-----")[0].strip()
                        headers = m.transport_headers or ""
                        to = re.search(r"^To: (.*)$", headers, re.M)
                        frm = re.search(r"^From: (.*)$", headers, re.M)
                        sent = "sent" in name.lower() or sender.lower() == owner
                        when = (m.client_submit_time if sent else m.delivery_time) or m.delivery_time or m.client_submit_time
                        if not when:
                            continue
                        hot = bool(re.search(r"https?://|drive\.google|attach|usb|cd|done|secur|data|request", body, re.I))
                        c.add("email", (f'Email sent: "{subject}"' if sent else f'Email from {sender}: "{subject}"'),
                              (f'{"Sent by" if sent else "Received from"} {sender}. Folder: {name}. '
                               + (f"It says: \u201c{own[:260]}\u201d" if own else "The message has no text of its own.")),
                              to_iso(when), "message submit time" if sent else "message delivery time",
                              f"Outlook mailbox {box.name}", path=str(box), detail=f"folder {name}",
                              severity=3 if hot else 2,
                              tags=["email", "sent" if sent else "received"] + (["deleted-items"] if "deleted" in name.lower() else []),
                              entities=[Entity("person", f"person:{sender.lower()}", sender)] if sender else [],
                              data={"subject": subject, "sender": sender, "folder": name, "body": body[:1200],
                                    "from": frm.group(1).strip() if frm else "", "to": to.group(1).strip() if to else "",
                                    "attachments": getattr(m, "number_of_attachments", 0)})
                        n += 1
                    except Exception as exc:
                        c.dropped[f"unreadable messages ({type(exc).__name__})"] += 1
                for i in range(folder.number_of_sub_folders):
                    sub = folder.get_sub_folder(i)
                    walk(sub, sub.name or "folder")

            walk(pff.get_root_folder(), "root")
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
            # A secure eraser renames the file several times, in a burst, to random names as long as the original.
            scrambled = sum(1 for x in items if len(x[2]) == len(first_old) and x[2] != first_old)
            if (len(items) >= 5 and span <= timedelta(seconds=20) and scrambled >= 0.8 * len(items)
                    and dele and dele - items[-1][0] <= timedelta(minutes=10)):
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
                if old.startswith(("~", "$")) or new.startswith(("~", "$")):
                    c.dropped["temporary-file renames by Office"] += 1
                    continue
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
    _section(c, "opened files (shortcuts)", links)
    _section(c, "browsed folders (shellbags)", shellbags)
    _section(c, "Google Drive sync log", gdrive)
    _section(c, "email (Outlook mailbox)", mail)
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
