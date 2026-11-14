"""Score a case against a published answer key.

The answer key is read here and nowhere else. No agent or examiner sees it.
Each check reports found / expected and lists what was missed, so a low score
can be traced to specific items.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional
from zoneinfo import ZoneInfo

from .ledger import Case, CaseStore

EVAL_DIR = Path(__file__).resolve().parent.parent / "eval"
FAMILY = {"OLE2": {"DOC", "XLS", "PPT", "OLE2"}}


def load_reference(name: str) -> Optional[dict]:
    p = EVAL_DIR / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else None


def _utc(local_iso: str, tz: ZoneInfo) -> datetime:
    return datetime.fromisoformat(local_iso).replace(tzinfo=tz)


def _type_ok(found: str, truth: str) -> bool:
    return found == truth or found in FAMILY.get(truth, ()) or truth in FAMILY.get(found, ())


def _strip(name: str) -> str:
    return re.sub(r"^[\[(]secret_project[\])]_", "", name.lower())


def _check(name: str, label: str, found: list, expected: list, note: str = "", ran: bool = True) -> dict:
    return {"id": name, "label": label, "ran": ran, "found": len(found), "expected": len(expected),
            "score": round(len(found) / len(expected), 3) if expected and ran else None,
            "missed": [e for e in expected if e not in found][:30], "note": note}


def reference_events(ref: dict, tz_name: str) -> list[dict]:
    tz = ZoneInfo(tz_name)
    out = []
    for i, e in enumerate(ref.get("events", [])):
        out.append({**e, "id": f"ref{i + 1:02d}", "time": _utc(e["time"], tz).isoformat(),
                    "time_end": _utc(e["time_end"], tz).isoformat() if e.get("time_end") else None})
    return out


def score(case: Case, store: CaseStore, ref: dict) -> dict[str, Any]:
    tz = ZoneInfo(ref.get("timezone", case.timezone))
    findings = store.load_findings(case.id)
    examined = {f["data"].get("image_id") for f in findings}
    by_img = lambda img, kinds: [f for f in findings if f["data"].get("image_id") == img and f["kind"] in kinds]
    checks = []

    # 1. Image integrity.
    imgs = [im for im in case.images if im.sha1_expected]
    ok = [im.id for im in imgs if im.sha1_actual and im.sha1_actual.upper() == im.sha1_expected.upper()]
    checks.append(_check("integrity", "Evidence images match their published SHA-1", ok, [im.id for im in imgs],
                         "Large images are verified by fetch_dataset.sh instead."))

    # 2. RM#2: deleted files recovered with the right content type.
    truth2 = ref.get("rm2_files", [])
    rec = {f["data"]["name"].lower(): f for f in by_img("rm2", ("deleted_file_recovered",))}
    got = [t["name"] for t in truth2
           if t["name"].lower() in rec and _type_ok(rec[t["name"].lower()]["data"]["true_type"], t["true_type"])]
    checks.append(_check("rm2_recovery", "RM#2: files recovered after the quick format, content type correct",
                         got, [t["name"] for t in truth2], ran="rm2" in examined))
    sized = [t["name"] for t in truth2 if t["name"].lower() in rec
             and abs(rec[t["name"].lower()]["data"]["size"] - t["size"]) <= max(0.02 * t["size"], 1024)]
    checks.append(_check("rm2_sizes", "RM#2: recovered file sizes agree with the answer key", sized,
                         [t["name"] for t in truth2], ran="rm2" in examined))

    # 3. RM#2: disguises flagged with the right true type.
    dz = {f["data"]["name"].lower(): f for f in by_img("rm2", ("disguised_file",))}
    got = [t["name"] for t in truth2
           if t["name"].lower() in dz and _type_ok(dz[t["name"].lower()]["data"]["actual"], t["true_type"])]
    checks.append(_check("rm2_disguise", "RM#2: disguised files flagged with their true type", got,
                         [t["name"] for t in truth2], ran=any(f["agent"] == "disguise" for f in findings)))

    # 4. RM#2: quick format detected and dated.
    fm = by_img("rm2", ("volume_formatted",))
    window = ref.get("devices", {}).get("rm2", {}).get("formatted")
    dated = []
    if fm and window:
        t = datetime.fromisoformat(fm[0]["time"]) if fm[0].get("time") else None
        if t and _utc(window[0], tz) <= t <= _utc(window[1], tz) and fm[0]["data"].get("time_precise"):
            dated = ["format time"]
    checks.append(_check("rm2_format", "RM#2: quick format detected", ["format"] if fm else [], ["format"],
                         ran=any(f["agent"] == "wiper" and f["data"].get("image_id") == "rm2" for f in findings) or bool(fm)))
    checks.append(_check("rm2_format_time", "RM#2: format dated inside the answer-key window", dated,
                         ["format time"], ran=bool(fm)))

    # 5. RM#3: carved documents by type and size.
    truth3 = ref.get("rm3_files", [])
    carved = [f for f in by_img("rm3", ("carved_file",)) if f["data"]["true_type"] not in ("JPEG", "PNG")]
    used: set[str] = set()
    got = []
    for t in truth3:
        for f in carved:
            if f["id"] in used or not _type_ok(f["data"]["true_type"], t["true_type"]):
                continue
            if t["size"] is None or abs(f["data"]["size"] - t["size"]) <= max(0.04 * t["size"], 2048):
                used.add(f["id"])
                got.append(t["name"])
                break
    checks.append(_check("rm3_carving", "RM#3: deleted documents carved from the CD-R (type and size)", got,
                         [t["name"] for t in truth3], "One file is only partly recoverable per the answer key.",
                         ran="rm3" in examined))

    # 6. PC: disguising renames from the change journal.
    renames = [f for f in findings if f["kind"] == "file_renamed" and f.get("time")]
    got, exp = [], []
    for r in ref.get("renames", []):
        label = f"{r['old']} > {r['new']} ({r['time'][5:16].replace('T', ' ')})"
        exp.append(label)
        t0 = _utc(r["time"], tz)
        for f in renames:
            if f["data"].get("new_name", "").lower() == r["new"].lower() and \
                    abs(datetime.fromisoformat(f["time"]) - t0) <= timedelta(minutes=2):
                got.append(label)
                break
    checks.append(_check("pc_renames", "PC: disguising renames recovered from the change journal", got, exp,
                         ran="pc" in examined))

    # 7. Timeline: reference events with a matching finding.
    ev = reference_events(ref, ref.get("timezone", case.timezone))
    matches = {}
    got, exp = [], []
    for e in ev:
        if e["needs"] not in examined:
            continue
        exp.append(e["title"])
        t0 = datetime.fromisoformat(e["time"])
        t1 = datetime.fromisoformat(e["time_end"]) if e.get("time_end") else t0
        win = timedelta(minutes=e.get("window_min", 5))
        best = None
        for f in findings:
            if not f.get("time") or (e["kinds"] and f["kind"] not in e["kinds"]):
                continue
            t = datetime.fromisoformat(f["time"])
            if not (t0 - win <= t <= t1 + win):
                continue
            hay = (f["title"] + " " + f.get("summary", "") + " " + json.dumps(f.get("data", {}))).lower()
            if e["terms"] and not any(term.lower() in hay for term in e["terms"]):
                continue
            if best is None or f["severity"] > best["severity"]:
                best = f
        if best:
            got.append(e["title"])
            matches[e["id"]] = best["id"]
    checks.append(_check("timeline", "Timeline: answer-key events with a matching, evidenced finding", got, exp,
                         "Email events need mailbox parsing, which is not implemented yet.",
                         ran=bool(exp)))

    ran = [c for c in checks if c["ran"] and c["score"] is not None]
    result = {
        "reference": ref["name"], "source": ref.get("answer_key"), "note": ref.get("note"),
        "checks": checks, "matches": matches,
        "overall": round(sum(c["found"] for c in ran) / max(1, sum(c["expected"] for c in ran)), 3) if ran else None,
        "examined": sorted(x for x in examined if x),
    }
    store.save_json(case.id, "score.json", result)
    return result
