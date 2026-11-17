"""Disguise agent: catch files hiding under false names.

Two independent checks:
1. Name against content. The extension says one thing, the bytes say another.
   We look inside containers, so a PowerPoint renamed to .zip is still caught.
2. Identity across devices. The same bytes under a different name somewhere
   else in the case reveal what a disguised file really is.

This agent reads the ledger (what intake and recovery already established)
and never touches a file it cannot cite.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable

from ..ledger import Case, CaseStore
from ..magic import check_disguise
from ..models import Entity, Evidence, Finding, file_entity

AGENT = "disguise"
Log = Callable[[str], None]
FILE_KINDS = ("file_listed", "deleted_file_recovered", "carved_file")
_GENERIC = ("carved_",)


def _is_real_name(d: dict) -> bool:
    name = d.get("data", {}).get("name") or ""
    if d["kind"] == "carved_file" and not d["data"].get("named"):
        return False
    return bool(name) and not name.startswith(_GENERIC)


def _ev(d: dict) -> list[Evidence]:
    return [Evidence(**e) for e in d.get("evidence", [])]


def run_case(case: Case, store: CaseStore, log: Log = print) -> list[Finding]:
    files = [f for f in store.load_findings(case.id) if f["kind"] in FILE_KINDS and f.get("data", {}).get("true_type")]
    findings: list[Finding] = []

    # 1. Name against content.
    flagged: dict[str, Finding] = {}
    for f in files:
        if not _is_real_name(f):
            continue
        d = f["data"]
        verdict = check_disguise(d["name"], d["true_type"])
        if not verdict:
            continue
        ev = _ev(f)
        if ev:
            ev[0].detail = f"extension .{verdict['claimed']}, content signature {verdict['actual']}"
        doc = d.get("doc") or {}
        hint = doc.get("title") or doc.get("first_text")
        fd = Finding(
            kind="disguised_file", agent=AGENT,
            title=f"{d['name']} is really a {verdict['actual']} document" if verdict["severity"] == 3
            else f"{d['name']} does not match its extension",
            summary=(f"{verdict['reason']}. " + (f"Inside, the document reads: \"{hint[:100]}\". " if hint else "")
                     + f"Found on {next((e['label'] for e in f['entities'] if e['type'] == 'device'), 'the device')}."),
            time=f.get("time"), time_source=f.get("time_source"),
            entities=[Entity(**e) for e in f["entities"]],
            evidence=ev, confidence=0.97, severity=verdict["severity"],
            tags=["disguised", f"claimed-{verdict['claimed']}", f"actual-{verdict['actual'].lower()}"],
            data={"image_id": d.get("image_id"), "name": d["name"], "path": d.get("path"),
                  "claimed": verdict["claimed"], "actual": verdict["actual"], "sha256": d.get("sha256"),
                  "based_on": f["id"], "inner_title": hint},
        )
        findings.append(fd)
        flagged[f["id"]] = fd
    log(f"{len(findings)} files carry an extension that does not match their content")

    # 2. Identity across devices: same content, different name or place.
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in files:
        d = f["data"]
        if d.get("sha256"):
            groups["sha256:" + d["sha256"]].append(f)
    # Carved copies can be a few bytes longer or shorter than the original.
    # Fall back to the first 16 KB for files no exact group already links.
    linked = {f["id"] for g in groups.values() if len({x["data"].get("image_id") for x in g}) > 1 for f in g}
    heads: dict[str, list[dict]] = defaultdict(list)
    for f in files:
        h = f["data"].get("head16")
        if h:
            heads[h].append(f)
    for h, g in heads.items():
        if len({x["data"].get("image_id") for x in g}) > 1 and not all(x["id"] in linked for x in g):
            groups["head16:" + h] = g

    n_links = 0
    for key, g in groups.items():
        images = {x["data"].get("image_id") for x in g}
        names = {x["data"]["name"] for x in g if _is_real_name(x)}
        if len(images) < 2 and len(names) < 2:
            continue
        exact = key.startswith("sha256:")
        g = sorted(g, key=lambda x: (x.get("time") or "9999", x["data"].get("image_id") or ""))
        honest = [x for x in g if _is_real_name(x) and not check_disguise(x["data"]["name"], x["data"]["true_type"])]
        true_name = honest[0]["data"]["name"] if honest else None
        places = []
        for x in g:
            dev = next((e["label"] for e in x["entities"] if e["type"] == "device"), "?")
            nm = x["data"]["name"] if _is_real_name(x) else "an unnamed carved copy"
            places.append(f"{nm} on {dev}")
        ent = file_entity(g[0]["data"].get("sha256"), true_name or sorted(names)[0] if names else "carved file")
        ents = {(e["type"], e["id"]): Entity(**e) for x in g for e in x["entities"]}
        ents[(ent.type, ent.id)] = ent
        evidence = []
        for x in g:
            for e in _ev(x)[:1]:
                evidence.append(e)
        title = (f"{true_name} appears under {len(names) - 1} false name(s)" if true_name and len(names) > 1
                 else f"Same content on {len(images)} devices")
        findings.append(Finding(
            kind="evidence_link", agent=AGENT, title=title,
            summary=(("Byte-for-byte identical content: " if exact else "Identical first 16 KB of content: ")
                     + "; ".join(places) + "."
                     + (f" The undisguised copy is named {true_name}." if true_name and len(names) > 1 else "")),
            entities=list(ents.values()), evidence=evidence,
            confidence=0.99 if exact else 0.85, severity=3 if (true_name and len(names) > 1) else 2,
            tags=["link", "exact" if exact else "partial"],
            data={"match": key, "true_name": true_name, "names": sorted(names),
                  "images": sorted(i for i in images if i), "members": [x["id"] for x in g]},
        ))
        n_links += 1
        if true_name:
            for x in g:
                fd = flagged.get(x["id"])
                if fd and x["data"]["name"] != true_name:
                    fd.data["true_name"] = true_name
                    fd.summary += f" Identical content exists elsewhere in the case as {true_name}."
    log(f"{n_links} files were matched across devices or names by content")

    # 3. The computer's change journal: a rename from a document name to a media name, before the copy.
    renames = sorted((f for f in store.load_findings(case.id) if f["kind"] == "file_renamed" and f.get("time")
                      and f["data"].get("old_name") and f["data"].get("new_name")), key=lambda f: f["time"])
    named = 0
    for fd in flagged.values():
        if not fd.time:
            continue
        before = [r for r in renames if r["data"]["new_name"].lower() == fd.data["name"].lower() and r["time"] <= fd.time]
        if not before:
            continue
        r = before[-1]
        original = r["data"]["old_name"]
        agrees = fd.data.get("true_name") in (None, original)
        fd.data.setdefault("true_name", original)
        fd.data["renamed_by"] = r["id"]
        fd.data["supports"] = sorted(set(fd.data.get("supports", [])) | {r["id"]})
        fd.summary += (f" The computer's change journal shows {original} being renamed to {fd.data['name']} "
                       f"before this copy was made" + ("." if agrees else
                                                      f", while identical content elsewhere is named {fd.data['true_name']}."))
        fd.evidence += [Evidence(**{**e, "detail": f"rename on the computer: {original} to {fd.data['name']}"}) for e in r["evidence"][:1]]
        fd.confidence = 0.99
        named += 1
    if named:
        log(f"{named} disguised files traced back to their original name through the computer's rename records")
    return findings
