"""Consensus agent: merge what every examiner found into one account in time.

It does not look at any image. It reads the ledger, lines findings up on one
clock, groups them into story beats, follows each file across devices, counts
how many independent agents back each beat, and lists what does not add up.

Everything here is deterministic. An LLM can be asked to write the narrative
on top (see agents.py), but it can only cite beats and findings built here.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Optional

from .ledger import Case, CaseStore
from .models import LANES, now_iso

AGENT = "consensus"
GAP = timedelta(minutes=4)
PHASES = ["preparation", "collection", "exfiltration", "cover-up", "context"]

_PHASE = {
    "web_search": "preparation", "web_visit": "preparation", "program_installed": "preparation",
    "usb_connected": "collection", "file_opened": "collection", "file_copied": "collection",
    "file_created": "collection", "file_listed": "collection",
    "deleted_file_recovered": "exfiltration", "carved_file": "exfiltration", "cd_burned": "exfiltration",
    "cloud_activity": "exfiltration", "email": "exfiltration", "web_download": "preparation",
    "disguised_file": "cover-up", "file_renamed": "cover-up", "volume_formatted": "cover-up",
    "file_deleted": "cover-up", "recycle_bin": "cover-up", "wiping_tool": "cover-up",
    "file_wiped": "cover-up", "program_uninstalled": "cover-up",
    "evidence_link": "exfiltration", "program_executed": "context", "system_info": "context", "note": "context",
}


def _t(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


def _device(f: dict) -> Optional[dict]:
    return next((e for e in f.get("entities", []) if e["type"] == "device"), None)


def _local(case: Case, iso: str) -> datetime:
    return _t(iso).astimezone(case.tz)


def _span(case: Case, a: str, b: str) -> str:
    x, y = _local(case, a), _local(case, b)
    if (y - x).total_seconds() < 60:
        return f"At {x:%H:%M}"
    return f"Between {x:%H:%M} and {y:%H:%M}"


def _names(items: list[dict], limit: int = 3) -> str:
    names = []
    for f in items:
        n = f.get("data", {}).get("name") or f["title"]
        if n not in names:
            names.append(n)
    more = len(names) - limit
    return ", ".join(names[:limit]) + (f" and {more} more" if more > 0 else "")


def _beat_text(case: Case, kind: str, dev: Optional[dict], items: list[dict]) -> tuple[str, str]:
    n = len(items)
    where = dev["label"] if dev else "the computer"
    when = _span(case, items[0]["time"], items[-1]["time"])
    d0 = items[0].get("data", {})
    if kind == "deleted_file_recovered":
        size = sum(f["data"].get("size", 0) for f in items) / 1048576
        return (f"{n} file{'s' if n != 1 else ''} written to {where}",
                f"{when}, {n} file{'s' if n != 1 else ''} ({size:.1f} MB) {'were' if n != 1 else 'was'} written to {where}, deleted later, and recovered: "
                f"{_names(items)}.")
    if kind == "file_listed":
        return (f"{n} file{'s' if n != 1 else ''} written to {where}",
                f"{when}, {n} file{'s' if n != 1 else ''} {'were' if n != 1 else 'was'} written to {where} and {'are' if n != 1 else 'is'} still there: {_names(items)}.")
    if kind == "carved_file":
        return (f"{n} file{'s' if n != 1 else ''} written to {where}",
                f"{when}, {n} file{'s' if n != 1 else ''} {'were' if n != 1 else 'was'} written to {where}. No longer listed there, carved back from raw data.")
    if kind == "disguised_file":
        kinds = Counter(f["data"].get("actual", "?") for f in items)
        mix = ", ".join(f"{c} {k}" for k, c in kinds.most_common())
        return (f"{n} disguised file{'s' if n != 1 else ''} on {where}",
                f"{n} files on {where} carry false extensions ({mix}): {_names(items)}.")
    if kind == "file_renamed":
        ex = items[0]["data"]
        return (f"{n} file{'s' if n != 1 else ''} renamed to hide what they are",
                f"{when}, {n} document{'s' if n != 1 else ''} {'were' if n != 1 else 'was'} renamed to unrelated names and extensions, for example "
                f"{ex.get('old_name')} became {ex.get('new_name')}.")
    if kind == "volume_formatted":
        return (f"{where} was quick-formatted", items[0]["summary"])
    if kind == "usb_connected":
        return (items[0]["title"], items[0]["summary"])
    if kind == "web_search":
        qs = []
        for f in items:
            q = f["data"].get("query")
            if q and q not in qs:
                qs.append(q)
        return (f"{len(qs) or n} web search{'es' if (len(qs) or n) != 1 else ''}",
                f"{when} the user searched for: " + "; ".join(f'"{q}"' for q in qs[:6])
                + (f" and {len(qs) - 6} more." if len(qs) > 6 else "."))
    if kind == "wiping_tool":
        tools = sorted({f["data"].get("tool", "a wiping tool") for f in items})
        return (f"Wiping tool activity: {', '.join(tools)}",
                " ".join(dict.fromkeys(f["title"] + "." for f in items)))
    if kind == "file_wiped":
        return (f"{n} file{'s' if n != 1 else ''} securely wiped",
                f"{when}, {n} file{'s' if n != 1 else ''} {'were' if n != 1 else 'was'} overwritten, renamed to random names and deleted: {_names(items)}.")
    if kind == "recycle_bin":
        return (f"{n} item{'s' if n != 1 else ''} sent to the Recycle Bin",
                f"{when}, {n} item{'s' if n != 1 else ''} {'were' if n != 1 else 'was'} deleted to the Recycle Bin: {_names(items)}.")
    if kind == "file_deleted":
        return (f"{n} file{'s' if n != 1 else ''} deleted on {where}",
                f"{n} files were removed from view on {where}: {_names(items)}.")
    if kind == "file_opened":
        return (f"{n} file{'s' if n != 1 else ''} opened", f"{when} the user opened: {_names(items, 4)}.")
    if kind == "program_installed":
        return (f"Installed {_names(items)}", f"{when}: {_names(items, 5)} installed.")
    if kind == "program_executed":
        return (f"Ran {_names(items)}", f"{when} the user ran: {_names(items, 6)}.")
    if kind == "web_download":
        return (f"Downloaded {_names(items)}", f"{when}: downloaded {_names(items, 4)}.")
    if kind == "cloud_activity":
        return (f"Cloud storage activity ({d0.get('service') or 'cloud'})", f"{when}: " + "; ".join(
            dict.fromkeys(f["title"] for f in items[:4])) + ".")
    if kind == "evidence_link":
        return (items[0]["title"], items[0]["summary"])
    return (items[0]["title"] if n == 1 else f"{n} × {kind.replace('_', ' ')}", items[0]["summary"])


def build(case: Case, store: CaseStore) -> dict[str, Any]:
    findings = store.load_findings(case.id)
    reviews = store.load_json(case.id, "reviews.json", {}) or {}
    for f in findings:
        f["review"] = reviews.get(f["id"], {"status": "unreviewed"})
    active = [f for f in findings if f["review"].get("status") != "rejected"]
    timed = sorted((f for f in active if f.get("time")), key=lambda f: (f["time"], f["kind"], f["id"]))
    undated = [f for f in active if not f.get("time")]

    # -- file journeys: one identity, every sighting ------------------------
    by_sha: dict[str, list[dict]] = defaultdict(list)
    for f in active:
        if f["kind"] in ("file_listed", "deleted_file_recovered", "carved_file") and f["data"].get("sha256"):
            by_sha[f["data"]["sha256"]].append(f)
    alias: dict[str, str] = {}
    link_of: dict[str, dict] = {}
    by_id = {f["id"]: f for f in active}
    for f in active:
        if f["kind"] != "evidence_link":
            continue
        shas = sorted({by_id[m]["data"]["sha256"] for m in f["data"].get("members", [])
                       if m in by_id and by_id[m]["data"].get("sha256")})
        if not shas:
            continue
        root = alias.get(shas[0], shas[0])
        for s in shas:
            alias[s] = root
        link_of[root] = f
    disguises = {f["data"].get("based_on"): f for f in active if f["kind"] == "disguised_file"}
    merged: dict[str, list[dict]] = defaultdict(list)
    for sha, items in by_sha.items():
        merged[alias.get(sha, sha)].extend(items)
    journeys = []
    for root, items in merged.items():
        items.sort(key=lambda f: (f.get("time") or "9999", f["data"].get("image_id") or ""))
        link = link_of.get(root)
        sightings = []
        for f in items:
            dev = _device(f)
            dz = disguises.get(f["id"])
            sightings.append({
                "finding": f["id"], "image_id": f["data"].get("image_id"), "device": dev["label"] if dev else "?",
                "name": f["data"].get("name"), "named": f["kind"] != "carved_file" or bool(f["data"].get("named")),
                "state": f["data"].get("state", "live"), "time": f.get("time"),
                "true_type": f["data"].get("true_type"), "size": f["data"].get("size"),
                "disguised": bool(dz), "disguise_finding": dz["id"] if dz else None,
            })
        devices = {s["image_id"] for s in sightings}
        names = {s["name"] for s in sightings if s["named"]}
        true_name = (link or {}).get("data", {}).get("true_name")
        if not true_name:
            honest = [s["name"] for s in sightings if s["named"] and not s["disguised"]]
            true_name = honest[0] if honest else None
        if not true_name:                                  # the disguise agent may know it from the computer's renames
            true_name = next((dz["data"]["true_name"] for f in items for dz in [disguises.get(f["id"])]
                              if dz and dz["data"].get("true_name")), None)
        # What the computer's journal says happened to this file: the disguising rename and the deletion.
        for rid in sorted({dz["data"]["renamed_by"] for f in items for dz in [disguises.get(f["id"])]
                           if dz and dz["data"].get("renamed_by")}):
            r = by_id.get(rid)
            if not r:
                continue
            dev = _device(r)
            sightings.append({
                "finding": r["id"], "image_id": r["data"].get("image_id"), "device": dev["label"] if dev else "?",
                "name": r["data"]["new_name"], "named": True, "state": "renamed", "time": r.get("time"),
                "true_type": items[0]["data"].get("true_type"), "size": None, "disguised": True,
                "disguise_finding": None, "was": r["data"]["old_name"]})
            devices.add(r["data"].get("image_id"))
        sightings.sort(key=lambda x: (x.get("time") or "9999", x.get("image_id") or ""))
        doc = next((f["data"].get("doc") for f in items if f["data"].get("doc")), {}) or {}
        journeys.append({
            "id": "j_" + root[:12], "sha256": root, "true_name": true_name,
            "label": true_name or (sorted(names)[0] if names else f"{items[0]['data'].get('true_type', 'file')} {root[:8]}"),
            "true_type": items[0]["data"].get("true_type"), "inner_title": doc.get("title") or doc.get("first_text"),
            "devices": sorted(d for d in devices if d), "names": sorted(names), "sightings": sightings,
            "link": link["id"] if link else None,
            "notable": len(devices) > 1 or any(s["disguised"] for s in sightings) or any(s["state"] != "live" for s in sightings),
        })
    journeys.sort(key=lambda j: (-len(j["devices"]), -sum(s["disguised"] for s in j["sightings"]), j["label"]))
    journey_of = {s["finding"]: j["id"] for j in journeys for s in j["sightings"]}

    # -- beats: runs of the same kind on the same device, close in time ------
    beats: list[dict] = []
    open_beats: dict[tuple, dict] = {}
    for f in timed:
        if f["kind"] in ("system_info", "note"):
            continue
        dev = _device(f)
        key = (f["kind"], dev["id"] if dev else None)
        b = open_beats.get(key)
        if b and _t(f["time"]) - _t(b["_last"]) <= GAP:
            b["_items"].append(f)
            b["_last"] = f["time"]
        else:
            b = {"_items": [f], "_last": f["time"], "_dev": dev, "kind": f["kind"]}
            open_beats[key] = b
            beats.append(b)
    out_beats = []
    for i, b in enumerate(beats):
        items = b.pop("_items")
        dev = b.pop("_dev")
        b.pop("_last")
        title, text = _beat_text(case, b["kind"], dev, items)
        agents = {f["agent"] for f in items}
        # Other agents that independently touch the same files or the same moment on the same device.
        ids = {f["id"] for f in items}
        jset = {journey_of[x] for x in ids if x in journey_of}
        for g in timed:
            if g["id"] in ids or g["agent"] in agents:
                continue
            same_file = g["data"].get("based_on") in ids or journey_of.get(g["id"]) in jset or \
                any(m in ids for m in g["data"].get("members", []))
            if same_file:
                agents.add(g["agent"])
        out_beats.append({
            "id": f"b{i + 1:03d}", "kind": b["kind"], "lane": items[0]["lane"],
            "phase": _PHASE.get(b["kind"], "context"),
            "time": items[0]["time"], "time_end": items[-1].get("time_end") or items[-1]["time"],
            "title": title, "text": text, "device": dev["label"] if dev else None,
            "findings": [f["id"] for f in items], "count": len(items),
            "severity": max(f["severity"] for f in items),
            "confidence": round(min(f["confidence"] for f in items), 2),
            "agents": sorted(agents), "agreement": len(agents),
        })

    # -- acts: one per local day, named by what dominated it -----------------
    acts = []
    by_day: dict[str, list[dict]] = defaultdict(list)
    for b in out_beats:
        by_day[_local(case, b["time"]).strftime("%Y-%m-%d")].append(b)
    for n, (day, bs) in enumerate(sorted(by_day.items()), 1):
        key = [b for b in bs if b["severity"] >= 2] or bs
        phases = Counter(b["phase"] for b in key if b["phase"] != "context")
        top = sorted(key, key=lambda b: (-b["severity"], -b["count"]))[:3]
        acts.append({
            "id": f"act{n}", "day": day, "label": _local(case, bs[0]["time"]).strftime("%a %d %b %Y"),
            "start": bs[0]["time"], "end": max(b["time_end"] for b in bs),
            "phase": phases.most_common(1)[0][0] if phases else "context",
            "headline": "; ".join(b["title"] for b in sorted(top, key=lambda b: b["time"])),
            "beats": [b["id"] for b in bs],
        })

    # -- cautions: what does not add up or needs a human --------------------
    cautions = []
    formats = [f for f in timed if f["kind"] == "volume_formatted"]
    for fm in formats:
        dev = _device(fm)
        if "time-lower-bound" in fm.get("tags", []):
            cautions.append({"level": "note", "finding": fm["id"],
                             "text": f"The format time of {dev['label'] if dev else 'the device'} is a lower bound, "
                                     "not an exact time."})
        for f in timed:
            if f["kind"] == "deleted_file_recovered" and _device(f) and dev and _device(f)["id"] == dev["id"] \
                    and f["time"] > fm["time"] and fm["data"].get("time_precise"):
                cautions.append({"level": "conflict", "finding": f["id"],
                                 "text": f"{f['data'].get('name')} claims a write time after the format of "
                                         f"{dev['label']}. One of the two clocks is wrong."})
    for f in active:
        if f["kind"] in ("deleted_file_recovered", "carved_file") and not f["data"].get("intact", True):
            cautions.append({"level": "check", "finding": f["id"],
                             "text": f"{f['data'].get('name')} was recovered but its content could not be validated. "
                                     "It may be partly overwritten."})
        if not f.get("evidence"):
            cautions.append({"level": "conflict", "finding": f["id"],
                             "text": f"\"{f['title']}\" has no evidence pointer and should not be relied on."})
    pending = [f for f in active if f.get("agent") == "lead" and f["review"].get("status") == "unreviewed"]
    for f in pending:
        cautions.append({"level": "review", "finding": f["id"],
                         "text": f"\"{f['title']}\" is an inference by the lead agent and awaits human review."})

    lanes = [{"id": l, "count": sum(1 for f in timed if f["lane"] == l)} for l in LANES]
    stats = {
        "findings": len(active), "timed": len(timed), "undated": len(undated), "beats": len(out_beats),
        "journeys": len(journeys), "notable_journeys": sum(1 for j in journeys if j["notable"]),
        "recovered": sum(1 for f in active if f["kind"] in ("deleted_file_recovered", "carved_file")),
        "disguised": sum(1 for f in active if f["kind"] == "disguised_file"),
        "coverup": sum(1 for f in active if f["lane"] == "coverup"),
        "agents": sorted({f["agent"] for f in active}),
        "rejected": len(findings) - len(active),
        "confirmed": sum(1 for f in active if f["review"].get("status") == "confirmed"),
    }
    timeline = {
        "case": case.to_dict(), "built": now_iso(), "timezone": case.timezone,
        "start": timed[0]["time"] if timed else None,
        "end": max((f.get("time_end") or f["time"]) for f in timed) if timed else None,
        "lanes": lanes, "events": timed, "undated": undated, "beats": out_beats, "acts": acts,
        "journeys": journeys, "cautions": cautions, "stats": stats,
    }
    store.save_json(case.id, "timeline.json", timeline)
    return timeline


def narrative(timeline: dict) -> str:
    """Plain-language account built only from beats. Used when no LLM is configured."""
    case = timeline["case"]
    lines = [f"# {case['name']}: what happened, in order", ""]
    beats = {b["id"]: b for b in timeline["beats"]}
    for act in timeline["acts"]:
        lines.append(f"## {act['label']}")
        for bid in act["beats"]:
            b = beats[bid]
            if b["severity"] < 2:
                continue
            ref = ", ".join(b["findings"][:3]) + (f" +{len(b['findings']) - 3}" if len(b["findings"]) > 3 else "")
            lines.append(f"- **{b['title']}.** {b['text']} [{ref}]")
        lines.append("")
    if timeline["cautions"]:
        lines.append("## Open points")
        for c in timeline["cautions"]:
            lines.append(f"- ({c['level']}) {c['text']} [{c['finding']}]")
    return "\n".join(lines)


def report_html(timeline: dict, narrative_md: str, written_by: str = "") -> str:
    """A printable report: the account in order, then an exhibit list with evidence pointers."""
    import html
    import re
    from zoneinfo import ZoneInfo

    case = timeline["case"]
    tz = ZoneInfo(timeline["timezone"])
    esc = html.escape

    def local(iso):
        return datetime.fromisoformat(iso).astimezone(tz).strftime("%a %d %b %Y, %H:%M:%S") if iso else "no time recorded"

    body = []
    in_list = False
    for raw in narrative_md.splitlines():
        line = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", esc(raw))
        line = re.sub(r"\b(f_[0-9a-f]{12})\b", r'<a href="#\1" class="cite">\1</a>', line)
        is_li = raw.lstrip().startswith(("- ", "* "))
        if is_li and not in_list:
            body.append("<ul>")
            in_list = True
        if not is_li and in_list:
            body.append("</ul>")
            in_list = False
        if raw.startswith("# "):
            continue
        if raw.startswith("#"):
            body.append(f"<h2>{line.lstrip('# ')}</h2>")
        elif is_li:
            body.append(f"<li>{line.lstrip()[2:]}</li>")
        elif raw.strip():
            body.append(f"<p>{line}</p>")
    if in_list:
        body.append("</ul>")

    rows = []
    exhibits = [f for f in timeline["events"] + timeline["undated"] if f["severity"] >= 2]
    for n, f in enumerate(exhibits, 1):
        ev = []
        for e in f["evidence"][:3]:
            bits = [esc(e["image"]), esc(e["source"])]
            if e.get("path"):
                bits.append(esc(e["path"]))
            if e.get("offset") is not None:
                bits.append(f"offset {e['offset']:,}" + (f", length {e['length']:,}" if e.get("length") else ""))
            if e.get("sha256"):
                bits.append(f"sha-256 {e['sha256']}")
            ev.append("<div>" + "<br>".join(bits) + "</div>")
        status = f["review"].get("status", "unreviewed")
        rows.append(f'<tr id="{f["id"]}"><td>{n}</td><td>{local(f.get("time"))}</td>'
                    f'<td><b>{esc(f["title"])}</b><br>{esc(f["summary"])}<br><span class="id">{f["id"]} · {esc(f["agent"])} agent'
                    f' · confidence {round(f["confidence"] * 100)}% · {status}</span></td><td class="ev">{"".join(ev)}</td></tr>')
    st = timeline["stats"]
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{esc(case['name'])}: case report</title>
<style>
body{{font:15px/1.55 Charter,'Iowan Old Style',Georgia,serif;color:#16233a;max-width:1000px;margin:36px auto;padding:0 28px}}
h1{{font-size:28px;margin:0 0 4px}} h2{{font-size:19px;margin:28px 0 8px;border-bottom:1px solid #d3d8df;padding-bottom:4px}}
.meta,.id,.ev,th{{font-family:'Avenir Next','Segoe UI',sans-serif}} .meta{{color:#47536a;font-size:13px}}
li{{margin:0 0 8px}} .cite{{font:11px ui-monospace,Menlo,monospace;color:#7c8799;text-decoration:none}}
table{{border-collapse:collapse;width:100%;font-size:13px}} th{{text-align:left;font-size:12px;color:#47536a;border-bottom:1px solid #16233a;padding:6px 8px 6px 0}}
td{{vertical-align:top;border-bottom:1px solid #e6e9ed;padding:8px 8px 8px 0}} .id{{font-size:11px;color:#7c8799}}
.ev{{font-size:11px;color:#47536a;word-break:break-all;width:34%}} .ev div{{margin-bottom:6px}}
tr:target td{{background:#fff7d6}} @media print{{body{{margin:0}} a{{color:inherit}}}}
</style></head><body>
<h1>{esc(case['name'])}</h1>
<p class="meta">Case report generated {timeline['built']} UTC. Times are shown in {esc(timeline['timezone'])}.
{st['findings']} findings from {len(st['agents'])} agents, {st['confirmed']} confirmed and {st['rejected']} rejected by a reviewer.
{esc(written_by)}</p>
<p>{esc(case.get('description', ''))}</p>
{''.join(body)}
<h2>Exhibits</h2>
<p class="meta">Every notable finding with the evidence needed to re-derive it from the original image.</p>
<table><thead><tr><th>No.</th><th>When</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
</body></html>"""
