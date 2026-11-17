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


def _text_lines(raw: Any) -> list[str]:
    """Message text as lines. Works for HTML and plain bodies alike."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    text = raw or ""
    if re.search(r"(?i)<(html|body|p|br|div)\b", text):
        text = re.sub(r"\s+", " ", text)                   # in HTML a line break in the source means nothing
    text = re.sub(r"(?is)<(style|script|head).*?</\1>", " ", text)
    text = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</h\d>", "\n", text)
    text = htmllib.unescape(re.sub(r"<[^>]+>", " ", text)).replace("\xa0", " ")
    return [re.sub(r"[ \t\r]+", " ", line).strip() for line in text.split("\n")]


def split_quotes(lines: list[str]) -> tuple[str, list[dict]]:
    """Split a message into its own text and the earlier messages it quotes.

    A reply carries the messages before it, each under a From / Sent / To / Subject header. Those quotes
    can outlive the originals when the originals are deleted from the mailbox.
    """
    heads = [i for i, line in enumerate(lines)
             if line.startswith("From:") and any(x.startswith("Sent:") for x in lines[i: i + 4])]
    own = " ".join(x for x in lines[: heads[0] if heads else len(lines)] if x and not x.startswith("-----Original"))
    quotes = []
    for k, i in enumerate(heads):
        end = heads[k + 1] if k + 1 < len(heads) else len(lines)
        block = lines[i:end]
        fields, body_at = {}, 0
        for j, line in enumerate(block[:8]):
            m = re.match(r"^(From|Sent|To|Cc|Subject):\s*(.*)$", line)
            if m:
                fields[m.group(1).lower()] = m.group(2).strip()
                body_at = j + 1
        body = " ".join(x for x in block[body_at:] if x and not x.startswith("-----Original"))
        when = None
        for fmt in ("%A, %B %d, %Y %I:%M %p", "%A, %B %d, %Y %H:%M", "%a, %d %b %Y %H:%M"):
            try:
                when = datetime.strptime(fields.get("sent", ""), fmt)
                break
            except ValueError:
                continue
        if when and fields.get("from"):
            quotes.append({"from": fields["from"], "to": fields.get("to", ""), "subject": fields.get("subject", ""),
                           "sent_local": when, "body": body})
    return own.strip(), quotes


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
    try:
        os_installed = t.install_date
    except Exception:
        os_installed = None

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
            elif urlparse(url).netloc.lower().startswith(("www.google.", "google.")) and urlparse(url).path == "/url":
                c.dropped["search-engine redirect links"] += 1
            elif any(k in low for k in CLOUD) or tool_match(low) or any(k in low for k in INTERESTING_VISIT):
                key = (urlparse(url).netloc + urlparse(url).path, to_iso(ts)[:16])
                if key in seen:
                    continue
                seen.add(key)
                host = urlparse(url).netloc.lower()
                cloud = next((v for k, v in CLOUD.items() if k in host), None)
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
                    known = tool_match(prog)
                    prog = known[1] if known else prog.title()
                    c.add("program_uninstalled", f"Uninstalled {prog}",
                          f"The uninstaller in the {prog} program folder was run, which removes the program.",
                          to_iso(ts0), "Prefetch last-run time of the uninstaller", "Windows Prefetch",
                          path=_s(_get(r, "prefetch")), detail=next((x for x in linked if "UNINST" in x.upper()), ""),
                          severity=3 if known else 2, tags=["prefetch", "uninstall"],
                          entities=[Entity("program", f"program:{prog.lower()}", prog)],
                          data={"name": prog})
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
            if not ts or ts.year < 1990 or (os_installed and ts < os_installed):
                c.dropped["components that came with Windows"] += 1
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
                    dev = image_device(vlabel, vsn) if vsn and target[:1].upper() != "C" else None
                    external = bool(share) or dev is not None or (target[1:2] == ":" and kind not in (None, 3))
                    where = (f"the network share {share}" if share else
                             f"{dev.label} (drive {target[:2]})" if dev else
                             f"the {DRIVE_KIND.get(kind, 'drive')} {target[:2]}" if target[1:2] == ":" else "an unknown location")
                    ext = extension_of(nm)
                    updated = (changed - born).total_seconds() >= 60
                    for when, first in ((born, True), (changed, False)):
                        if not first and not updated:
                            continue
                        key = (nm.lower(), to_iso(when)[:16])
                        if key in seen:
                            continue
                        seen.add(key)
                        if first and updated:
                            text = (f"{user} first opened an item named {nm}. Windows updated the shortcut on a later "
                                    f"opening, so the location it records now ({target or 'unknown'}) is from the last time.")
                        else:
                            text = (f"{user} opened {target or nm} from {where}."
                                    + (f" The volume there had serial number {vsn:08X}." if vsn and external else ""))
                        c.add("file_opened", f"Opened {nm}" if first else f"Opened {nm} again",
                              text, to_iso(when),
                              "shortcut creation time: first time this item was opened" if first
                              else "shortcut modification time: most recent time it was opened",
                              "Windows shortcut (LNK) in the Recent folder", path=str(f), detail=target,
                              severity=2 if (external or ext in OFFICE_EXT) and not is_folder else 1,
                              tags=["lnk"] + (["external-volume"] if external else []) + (["folder"] if is_folder else []),
                              entities=[dev] if dev and not (first and updated) else [],
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
            if "<CDBURN>" in loc:
                c.add("cd_burned", f"Files staged for burning to disc in drive {loc[:2]}",
                      f"Explorer showed the \"files ready to be written to the disc\" view for drive {loc[:2]}. "
                      "Windows shows it when files are waiting to be burned.",
                      to_iso(ts), "shellbag registry key time: when this view was last saved",
                      "user registry hive: Shellbags", path=_s(_get(r, "regf_key_path")), detail=raw,
                      severity=2, confidence=0.7, tags=["shellbag", "burn"], data={"name": "burn staging", "target": loc})
                n += 1
                continue
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
                        ("DOWNLOAD", "DELETE"): f"{name} was removed by a change made in the cloud",
                        ("DOWNLOAD", "CHANGE_ACL"): f"Sharing changed for {name} on Google Drive",
                        ("UPLOAD", "CHANGE_ACL"): f"Sharing changed for {name} on Google Drive"}.get(
                    (direction, action), f"Google Drive {action.lower()} {name}")
                size = sizes.get(name)
                c.add("cloud_activity", what,
                      f"The Google Drive client of {user} finished this change: {direction.lower()}, {action.lower()}, "
                      f"{name}" + (f" ({size:,} bytes)." if size else "."),
                      to_iso(when), "Google Drive sync log line time (the log records its own UTC offset)",
                      "Google Drive sync_log.log", path=str(log_path), detail=line[:300],
                      severity=3 if (up and action in ("CREATE", "DELETE")) or action == "CHANGE_ACL" else 1,
                      tags=["cloud", "google-drive", direction.lower(), action.lower()],
                      entities=[Entity("program", "program:googledrive", "Google Drive")],
                      data={"service": "Google Drive", "name": name, "direction": direction, "action": action, "size": size})
                n += 1
        return n

    def mail() -> int:
        """Outlook mailboxes, read with libpff when it is installed. Also recovers messages that are gone
        from the mailbox but still quoted inside later replies."""
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
        hot_re = re.compile(r"https?://|drive\.google|attach|sample|usb|\bcd\b|storage|done|secur|data|request", re.I)
        for user, box in boxes:
            owner = box.name.split("@")[0].split(".")[0].lower()
            pff = pypff.file()
            pff.open_file_object(box.open())
            real: list[tuple[str, datetime]] = []              # (subject, time) of messages still in the mailbox
            quoted: list[tuple[dict, str, str]] = []

            def walk(folder, name: str) -> None:
                nonlocal n
                for i in range(folder.number_of_sub_messages):
                    try:
                        m = folder.get_sub_message(i)
                        subject = (m.subject or "").strip()
                        sender = (m.sender_name or "").strip()
                        if "Sync Issues" in name or subject.startswith("Synchronization Log"):
                            continue
                        own, quotes = split_quotes(_text_lines(m.html_body or m.plain_text_body or b""))
                        headers = m.transport_headers or ""
                        to = re.search(r"^To: (.*)$", headers, re.M)
                        frm = re.search(r"^From: (.*)$", headers, re.M)
                        sent = "sent" in name.lower() or sender.lower() == owner
                        when = (m.client_submit_time if sent else m.delivery_time) or m.delivery_time or m.client_submit_time
                        if not when:
                            continue
                        real.append((subject.lower(), _t(to_iso(when))))
                        quoted.extend((q, subject, name) for q in quotes)
                        c.add("email", (f'Email sent: "{subject}"' if sent else f'Email from {sender}: "{subject}"'),
                              (f'{"Sent by" if sent else "Received from"} {sender}. Folder: {name}. '
                               + (f"It says: “{own[:260]}”" if own else "The message has no text of its own.")),
                              to_iso(when), "message submit time" if sent else "message delivery time",
                              f"Outlook mailbox {box.name}", path=str(box), detail=f"folder {name}",
                              severity=3 if hot_re.search(own) else 2,
                              tags=["email", "sent" if sent else "received"] + (["deleted-items"] if "deleted" in name.lower() else []),
                              entities=[Entity("person", f"person:{sender.lower()}", sender)] if sender else [],
                              data={"subject": subject, "sender": sender, "folder": name, "body": own[:1200],
                                    "from": frm.group(1).strip() if frm else "", "to": to.group(1).strip() if to else "",
                                    "quotes": len(quotes)})
                        n += 1
                    except Exception as exc:
                        c.dropped[f"unreadable messages ({type(exc).__name__})"] += 1
                for i in range(folder.number_of_sub_folders):
                    sub = folder.get_sub_folder(i)
                    walk(sub, sub.name or "folder")

            walk(pff.get_root_folder(), "root")
            # Messages that only survive as quotes inside later replies.
            seen_q = set()
            for q, inside, folder_name in quoted:
                iso = case.local_to_iso(q["sent_local"])
                key = (q["subject"].lower(), iso[:16], q["from"].lower())
                still_there = any(sub == q["subject"].lower() and abs((when - _t(iso)).total_seconds()) <= 180
                                  for sub, when in real)
                if key in seen_q or still_there:
                    continue
                seen_q.add(key)
                c.add("email", f'Email by {q["from"]}, recovered from a quote: "{q["subject"]}"',
                      (f'{q["from"]} wrote to {q["to"] or "the recipient"} at {q["sent_local"]:%H:%M} local time: '
                       f'“{q["body"][:260]}” This message is no longer in the mailbox. Its text survives because '
                       f'the later message "{inside}" quotes it.'),
                      iso, "sent time printed in the quoted header (local time, to the minute)",
                      f"Outlook mailbox {box.name}", path=str(box), detail=f'quoted inside "{inside}" in {folder_name}',
                      severity=3 if hot_re.search(q["body"]) else 2, confidence=0.8,
                      tags=["email", "quoted", "sent" if q["from"].lower() == owner else "received"],
                      entities=[Entity("person", f"person:{q['from'].lower()}", q["from"])],
                      data={"subject": q["subject"], "sender": q["from"], "to": q["to"], "body": q["body"][:1200],
                            "quoted_in": inside})
                n += 1
        return n

    def usn_records():
        """Yield (segment, time, reason, name, full_path_getter) for the journal records that matter.

        Reads the journal directly and resolves a full path only when asked,
        which is far faster than resolving every record.
        """
        def wanted(reason: str, name: str) -> bool:
            if "RENAME" in reason or "FILE_DELETE" in reason:
                return True
            return "FILE_CREATE" in reason and extension_of(name) in OFFICE_EXT and not name.startswith(("~", "$"))

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
                    name = rec.filename or ""
                    raw = rec.record
                    ref, up = raw.FileReferenceNumber, raw.ParentFileReferenceNumber
                    seg = f"{segment_reference(ref)}#{ref.SequenceNumber}"
                    parent = f"{segment_reference(up)}#{up.SequenceNumber}"
                    try:                                   # remember every folder the journal names
                        if int(raw.FileAttributes) & 0x10 and ("FILE_CREATE" in reason or "RENAME_NEW_NAME" in reason):
                            folders[seg] = (name, parent, up, fs)
                    except Exception:
                        pass
                    if not wanted(reason, name):
                        continue
                    try:
                        ts = rec.timestamp
                    except Exception:
                        continue
                    yield seg, ts, reason, name, (lambda r=rec, a=parent, b=up, f=fs, nm=name: _journal_path(r, a, b, f, nm))
            if seen_fs:
                return
        except Exception as exc:
            c.log(f"{image.label}: direct journal read failed ({exc}), using the slower reader")
        for r in t.usnjrnl():
            usn_total[0] += 1
            reason = _s(_get(r, "reason")).upper()
            ts = _get(r, "ts")
            path = _s(_get(r, "path"))
            if not ts or not wanted(reason, _name(path)):
                continue
            yield _s(_get(r, "segment_id")), ts, reason, _name(path), (lambda p=path: p)

    folders: dict[str, tuple] = {}

    def _journal_path(rec, parent: str, parent_ref, fs, name: str) -> str:
        """Full path of a journal record. When the folder it was in has since been deleted, the path is
        rebuilt from the journal's own records of that folder being created."""
        try:
            path = _s(rec.full_path).replace("/", "\\")
        except Exception:
            path = ""
        if path and "<broken_reference" not in path:
            return path
        parts, seg, ref, depth = [name], parent, parent_ref, 0
        while seg in folders and depth < 16:
            folder_name, seg, ref, _ = folders[seg]
            parts.append(folder_name)
            depth += 1
        top = ""
        try:
            top = _s(fs.ntfs.mft(ref).full_path()).replace("/", "\\")
        except Exception:
            top = ""
        if not top or "<broken_reference" in top:
            top = "(a folder that no longer exists)"
        return top + "\\" + "\\".join(reversed(parts))

    def _scratch(path: str, name: str) -> bool:
        """Temporary copies Office and the browser make on their own."""
        low = path.lower()
        return any(x in low for x in ("\\appdata\\local\\temp\\", "\\temporary internet files\\", "\\content.mso\\",
                                      "\\microsoft\\templates\\")) or bool(re.match(r"^[0-9A-F]{8}\.\w{3,4}$", name))

    usn_total = [0]

    def usn() -> int:
        """What the NTFS change journal remembers: documents arriving, disguising renames,
        moves to the Recycle Bin, deletions and the burst pattern of a secure eraser."""
        n = 0
        pending: dict[str, tuple[str, Any]] = {}
        renames: dict[str, list] = defaultdict(list)          # ts, old, new, new path getter, old path getter
        created: dict[str, tuple] = {}
        deleted: dict[str, tuple] = {}
        for seg, ts, reason, name, get_path in usn_records():
            if "RENAME_OLD_NAME" in reason:
                pending[seg] = (name, get_path)
            elif "RENAME_NEW_NAME" in reason:
                if seg in pending:
                    old, old_path = pending.pop(seg)
                    renames[seg].append((ts, old, name, get_path, old_path))
            elif "FILE_DELETE" in reason:
                deleted[seg] = (ts, name, get_path)
            elif "FILE_CREATE" in reason:
                created.setdefault(seg, (ts, name, get_path))

        def folder_of(path: str) -> str:
            return path.rsplit("\\", 1)[0] if "\\" in path else ""

        tracked: dict[str, str] = {}                           # segment -> how to describe the file when it is deleted
        for seg, (ts, name, get_path) in created.items():
            where = get_path()
            if _scratch(where, name):
                c.dropped["temporary copies made by Office or the browser"] += 1
                continue
            c.add("file_created", f"{name} appeared on the computer",
                  f"A new file named {name} was created" + (f" in {folder_of(where)}" if folder_of(where) else "")
                  + ". For a document that already exists elsewhere, this is the moment it was copied here.",
                  to_iso(ts), "NTFS change journal record time", "$UsnJrnl:$J", path=where or name,
                  severity=2, tags=["journal", "created"], data={"name": name, "path": where})
            tracked[seg] = name
            n += 1

        for seg, items in renames.items():
            rest = []
            i = 0
            while i < len(items):
                # A secure eraser renames the file several times in one burst, to random names as long as the original.
                j = i
                while j + 1 < len(items) and items[j + 1][0] - items[i][0] <= timedelta(seconds=20):
                    j += 1
                run = items[i: j + 1]
                first_old = run[0][1]
                scrambled = sum(1 for x in run if len(x[2]) == len(first_old) and x[2] != first_old)
                gone = deleted.get(seg)
                if len(run) >= 5 and scrambled >= 0.8 * len(run) and gone and timedelta(0) <= gone[0] - run[-1][0] <= timedelta(minutes=10):
                    where = run[0][4]() or first_old
                    c.add("file_wiped", f"{first_old} was overwritten and deleted",
                          f"{where} was renamed {len(run)} times in one burst to meaningless names such as "
                          f"\"{run[0][2]}\", and then deleted. A secure eraser does this to destroy the file name "
                          "after overwriting the content.",
                          to_iso(run[0][0]), "NTFS change journal record time", "$UsnJrnl:$J",
                          path=where, detail=" > ".join(x[2] for x in run[:8]),
                          severity=3, tags=["wiped", "anti-forensics"], time_end=to_iso(gone[0]),
                          data={"name": first_old, "path": where, "renames": len(run)})
                    n += 1
                    deleted.pop(seg, None)
                    i = j + 1
                    continue
                rest.append(items[i])
                i += 1
            for ts, old, new, get_path, old_path in rest:
                eo, en = extension_of(old), extension_of(new)
                if re.match(r"^\$R[0-9A-Z]{6}(\.|$)", new):       # Explorer renames a deleted item to $R... in the Recycle Bin
                    was = old_path() or old
                    c.add("recycle_bin", f"{old} sent to the Recycle Bin",
                          f"{was} was deleted to the Recycle Bin. The bin was emptied later, but the change journal "
                          f"still records the move (as {new}).",
                          to_iso(ts), "NTFS change journal record time", "$UsnJrnl:$J", path=was, detail=f"renamed to {new}",
                          severity=2, tags=["deleted", "journal"], data={"name": old, "original_path": was})
                    tracked[seg] = old
                    n += 1
                    continue
                if old.startswith(("~", "$")) or new.startswith(("~", "$")):
                    c.dropped["temporary-file renames by Office"] += 1
                    continue
                if eo == en or not (eo in OFFICE_EXT or en in OFFICE_EXT):
                    c.dropped["ordinary renames"] += 1
                    continue
                where = get_path()
                c.add("file_renamed", f"Renamed {old} to {new}",
                      f"{old} was renamed to {new}" + (f" in {folder_of(where)}" if folder_of(where) else "")
                      + f". The extension changed from .{eo or '(none)'} to .{en or '(none)'}.",
                      to_iso(ts), "NTFS change journal record time", "$UsnJrnl:$J", path=where or new, detail=f"was {old}",
                      severity=3 if eo in OFFICE_EXT else 2, tags=["rename", "extension-change"],
                      data={"old_name": old, "new_name": new, "new_path": where, "name": new})
                tracked[seg] = f"{new} (originally {old})" if eo in OFFICE_EXT else new
                n += 1

        for seg, (ts, name, get_path) in deleted.items():
            if seg not in tracked:
                continue
            if name.startswith("$R"):
                continue                                           # emptied from the Recycle Bin: already reported
            where = get_path()
            c.add("file_deleted", f"{name} deleted from the computer",
                  f"{tracked[seg]} was deleted" + (f" from {folder_of(where)}" if folder_of(where) else "")
                  + ". It did not go through the Recycle Bin.",
                  to_iso(ts), "NTFS change journal record time", "$UsnJrnl:$J", path=where or name,
                  severity=2, tags=["journal", "deleted"], data={"name": name, "path": where, "was": tracked[seg]})
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
