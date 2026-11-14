"""The agent team, built with LangChain deepagents.

A lead investigator plans the work and delegates to five specialists through
the deepagents `task` tool. The specialists do not reason about raw bytes.
They call deterministic examiners (the same ones the no-LLM pipeline runs) and
read the evidence ledger. That split is the point:

    the model proposes and explains, the tools compute, the ledger proves.

Guard rails:
- Agents can only cite findings that exist in the ledger. `write_report`
  rejects a report that cites an unknown finding id or cites nothing.
- An inference the lead wants to add goes in through `record_inference`,
  must name the findings it rests on, and stays "awaiting review" until a
  person confirms or rejects it in the UI.
- The answer key is not reachable from any tool.

Set ANTHROPIC_API_KEY (or CASEREPLAY_MODEL to any LangChain model string) to
enable this layer. Without a model the deterministic pipeline still runs.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Callable, Optional

from . import consensus, pipeline
from .ledger import CaseStore
from .models import Entity, Evidence, Finding

DEFAULT_MODEL = "anthropic:claude-sonnet-5-5"
CITE = re.compile(r"\bf_[0-9a-f]{12}\b")


def model_name() -> Optional[str]:
    if os.environ.get("CASEREPLAY_MODEL"):
        return os.environ["CASEREPLAY_MODEL"]
    if os.environ.get("ANTHROPIC_API_KEY"):
        return DEFAULT_MODEL
    return None


def llm_available() -> bool:
    return model_name() is not None


def _row(f: dict) -> dict:
    return {"id": f["id"], "kind": f["kind"], "time": f.get("time"), "title": f["title"],
            "agent": f["agent"], "severity": f["severity"], "image": f.get("data", {}).get("image_id")}


def make_tools(case_id: str, store: CaseStore, echo: Optional[Callable[[str], None]] = None) -> dict[str, Any]:
    """Tools bound to one case. Each returns compact JSON text."""

    def list_evidence() -> str:
        """List the evidence images in this case and which agents have already examined each one."""
        case = store.load_case(case_id)
        tasks = store.load_tasks(case_id)
        out = []
        for im in case.images:
            ran = sorted({t["agent"] for t in tasks if t["image_id"] == im.id and t["status"] == "done"})
            out.append({"image_id": im.id, "label": im.label, "kind": im.kind, "present": im.exists(),
                        "examined_by": ran})
        return json.dumps({"case": case.name, "timezone": case.timezone, "images": out,
                           "agents": {k: v["does"] for k, v in pipeline.AGENTS.items()}})

    def run_examiner(agent: str, image_id: str = "") -> str:
        """Run one deterministic examiner and store its findings in the ledger.

        agent: inventory | recovery | activity | disguise | wiper | consensus.
        image_id: which image to examine. Leave empty for disguise and consensus, which work on the whole case.
        Returns how many findings were stored and a sample of their titles.
        """
        if agent not in pipeline.AGENTS:
            return json.dumps({"error": f"unknown agent {agent}", "valid": list(pipeline.AGENTS)})
        case = store.load_case(case_id)
        image = case.image(image_id) if image_id else None
        if pipeline.AGENTS[agent]["scope"] == "image" and image is None:
            return json.dumps({"error": "this agent needs an image_id", "images": [i.id for i in case.images]})
        task = pipeline.run_task(store, case, agent, image, echo)
        mine = [f for f in store.load_findings(case_id)
                if f["agent"] == agent and (not image_id or f["data"].get("image_id") == image_id)]
        return json.dumps({"status": task["status"], "error": task["error"], "stored": task["findings"],
                           "seconds": task["seconds"], "by_kind": _count(mine),
                           "sample": [_row(f) for f in sorted(mine, key=lambda f: -f["severity"])[:8]]})

    def search_findings(kind: str = "", image_id: str = "", text: str = "", min_severity: int = 1,
                        limit: int = 25) -> str:
        """Search the evidence ledger. All filters are optional.

        kind: a finding kind such as deleted_file_recovered, disguised_file, volume_formatted, wiping_tool,
        web_search, usb_connected, file_renamed, evidence_link. text: case-insensitive substring.
        """
        text_l = text.lower()
        hits = []
        for f in store.load_findings(case_id):
            if kind and f["kind"] != kind:
                continue
            if image_id and f.get("data", {}).get("image_id") != image_id:
                continue
            if f["severity"] < min_severity:
                continue
            if text_l and text_l not in (f["title"] + " " + f.get("summary", "") + " " + json.dumps(f["data"])).lower():
                continue
            hits.append(f)
        hits.sort(key=lambda f: (f.get("time") or "9999", -f["severity"]))
        return json.dumps({"total": len(hits), "by_kind": _count(hits), "findings": [_row(f) for f in hits[:limit]]})

    def get_finding(finding_id: str) -> str:
        """Return one finding in full, including its evidence pointers (image, path, offset, hash)."""
        for f in store.load_findings(case_id):
            if f["id"] == finding_id:
                return json.dumps(f)
        return json.dumps({"error": f"no finding {finding_id}"})

    def get_timeline(day: str = "", min_severity: int = 2) -> str:
        """Return the consensus timeline as story beats in time order.

        day: optional local date YYYY-MM-DD. Each beat lists the finding ids it rests on and how many
        independent agents back it.
        """
        case = store.load_case(case_id)
        tl = consensus.build(case, store)
        beats = [b for b in tl["beats"] if b["severity"] >= min_severity]
        if day:
            ids = {x for a in tl["acts"] if a["day"] == day for x in a["beats"]}
            beats = [b for b in beats if b["id"] in ids]
        return json.dumps({
            "acts": [{k: a[k] for k in ("day", "label", "phase", "headline")} for a in tl["acts"]],
            "beats": [{"id": b["id"], "time": b["time"], "title": b["title"], "text": b["text"],
                       "phase": b["phase"], "agreement": b["agreement"], "findings": b["findings"][:6]}
                      for b in beats[:60]],
            "cautions": tl["cautions"][:20], "stats": tl["stats"]})

    def follow_file(name_or_hash: str) -> str:
        """Follow one file across every device: each place it was seen, under which name, in which state."""
        case = store.load_case(case_id)
        tl = consensus.build(case, store)
        q = name_or_hash.lower()
        out = [j for j in tl["journeys"]
               if q in j["sha256"] or q in (j["label"] or "").lower() or any(q in n.lower() for n in j["names"])]
        return json.dumps({"matches": len(out), "journeys": out[:5]})

    def record_inference(title: str, summary: str, supporting_finding_ids: list[str], time: str = "") -> str:
        """Add a conclusion that goes beyond a single artifact, for a human to review.

        It must rest on findings already in the ledger. Give their ids. It is stored as "awaiting review"
        and does not count as established until a person confirms it.
        """
        known = {f["id"]: f for f in store.load_findings(case_id)}
        missing = [i for i in supporting_finding_ids if i not in known]
        if missing or not supporting_finding_ids:
            return json.dumps({"error": "every inference must cite existing findings", "unknown_ids": missing})
        ev, ents = [], {}
        for i in supporting_finding_ids:
            for e in known[i]["evidence"][:1]:
                ev.append(Evidence(**{**e, "detail": f"via {i}: {known[i]['title']}"[:240]}))
            for e in known[i]["entities"]:
                ents[e["id"]] = Entity(**e)
        f = Finding(kind="note", agent="lead", title=title[:160], summary=summary, time=time or None,
                    time_source="stated by the lead agent" if time else None, entities=list(ents.values()),
                    evidence=ev, confidence=0.6, severity=2, tags=["inference", "needs-review"],
                    data={"supports": supporting_finding_ids})
        existing = [Finding.from_dict(x) for x in store.load_findings(case_id) if x["agent"] == "lead"]
        store.replace_findings(case_id, "lead", None, existing + [f])
        return json.dumps({"stored": f.id, "status": "awaiting human review"})

    def write_report(markdown: str) -> str:
        """Save the final case narrative. Every claim must cite finding ids like [f_0123456789ab].

        The report is rejected if it cites an id that is not in the ledger, or cites nothing.
        """
        known = {f["id"] for f in store.load_findings(case_id)}
        cited = set(CITE.findall(markdown))
        unknown = sorted(cited - known)
        if unknown or not cited:
            return json.dumps({"saved": False, "unknown_ids": unknown,
                               "error": "cite at least one finding and only ids that exist in the ledger"})
        path = store.case_dir(case_id) / "report.md"
        path.write_text(markdown)
        store.log(case_id, "lead", f"report written, {len(cited)} findings cited")
        return json.dumps({"saved": True, "cited": len(cited)})

    return {f.__name__: f for f in (list_evidence, run_examiner, search_findings, get_finding, get_timeline,
                                    follow_file, record_inference, write_report)}


def _count(findings: list[dict]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f["kind"]] = out.get(f["kind"], 0) + 1
    return out


LEAD_PROMPT = """You are the lead investigator on a digital forensics case. You direct a team of specialist \
agents and you answer to a prosecutor, so every statement you make must be checkable.

How you work:
1. Call list_evidence to see the images and what has been examined.
2. Delegate with the task tool. Give each specialist a concrete job (which image, what to look for). \
Run intake first, then recovery and activity, then disguise and wiper, then consensus.
3. Read the consensus timeline. Use follow_file on the most important files.
4. If you conclude something no single artifact shows (for example intent, or that two events are linked), \
store it with record_inference and cite the findings it rests on.
5. Finish with write_report: a short account in time order for a non-technical reader. Plain sentences. \
Every claim ends with the finding ids that prove it, like [f_0123456789ab]. State what is not known.

Rules: never state a file name, time, hash or count that you did not get from a tool. Never guess. \
If the tools found nothing, say so. Times in the ledger are UTC. Give local time using the case timezone."""

SPECIALISTS = [
    ("intake-agent", "Verifies evidence images and lists what each one shows today. Use first on every image.",
     "You are the intake specialist. For each image you are given, call run_examiner with agent='inventory'. "
     "Report the volume type, label, hash status and how many live files there are. Cite finding ids.",
     ("list_evidence", "run_examiner", "search_findings", "get_finding")),
    ("recovery-agent", "Recovers deleted files: surviving directory entries, old disc directories and carving.",
     "You are the recovery specialist. Call run_examiner with agent='recovery' on each storage image you are "
     "given. Report what was recovered, by which method, and anything that could not be validated. Cite ids.",
     ("list_evidence", "run_examiner", "search_findings", "get_finding")),
    ("disguise-agent", "Catches files hiding under false names and matches identical content across devices.",
     "You are the disguise specialist. Call run_examiner with agent='disguise' (no image_id). Then use "
     "search_findings(kind='disguised_file') and search_findings(kind='evidence_link'). Report each false "
     "name with the true type and, where known, the original name. Cite ids.",
     ("run_examiner", "search_findings", "get_finding", "follow_file")),
    ("wiper-agent", "Flags evidence destruction: quick formats, secure erasers, cleaners.",
     "You are the anti-forensics specialist. Call run_examiner with agent='wiper' on each image you are given. "
     "Report formats, wiping tools and wiped files with times. Say when a time is only a lower bound. Cite ids.",
     ("list_evidence", "run_examiner", "search_findings", "get_finding")),
    ("activity-agent", "Reconstructs what the user did on the computer: USB, searches, programs, renames.",
     "You are the computer activity specialist. Call run_examiner with agent='activity' on the computer image. "
     "Then summarise searches, device connections, installs and renames in time order. Cite ids.",
     ("list_evidence", "run_examiner", "search_findings", "get_finding")),
    ("consensus-agent", "Merges all findings into one timeline, checks agreement and lists contradictions.",
     "You are the consensus specialist. Call run_examiner with agent='consensus', then get_timeline. Report "
     "the sequence of events, which beats several agents agree on, and every caution. Do not add facts.",
     ("run_examiner", "get_timeline", "follow_file", "search_findings", "get_finding")),
]


def build_lead(case_id: str, store: CaseStore, model: Any = None, echo: Optional[Callable[[str], None]] = None):
    """Create the deep agent: a lead investigator with six specialist subagents."""
    from deepagents import create_deep_agent

    tools = make_tools(case_id, store, echo)
    subagents = [{"name": name, "description": desc, "system_prompt": prompt,
                  "tools": [tools[t] for t in names]} for name, desc, prompt, names in SPECIALISTS]
    return create_deep_agent(
        model=model or model_name(),
        tools=list(tools.values()),
        system_prompt=LEAD_PROMPT,
        subagents=subagents,
        name="lead-investigator",
    )


def investigate(case_id: str, store: CaseStore, question: str = "", model: Any = None,
                echo: Optional[Callable[[str], None]] = None) -> dict:
    """Run the lead investigator on a case. Streams tool activity into the case log."""
    agent = build_lead(case_id, store, model, echo)
    ask = question.strip() or ("Investigate this case from start to finish and write the report. "
                               "Explain what happened, in order, and what the suspect did to hide it.")
    store.log(case_id, "lead", f"lead investigator started: {ask[:140]}")
    final = ""
    steps = 0
    for chunk in agent.stream({"messages": [{"role": "user", "content": ask}]},
                              config={"recursion_limit": 120}, stream_mode="updates"):
        for node, update in (chunk or {}).items():
            for msg in (update or {}).get("messages", []) if isinstance(update, dict) else []:
                steps += 1
                calls = getattr(msg, "tool_calls", None) or []
                for c in calls:
                    args = c.get("args", {})
                    label = args.get("subagent_type") or args.get("agent") or ""
                    line = f"calls {c['name']}" + (f" ({label})" if label else "")
                    store.log(case_id, "lead", line)
                    if echo:
                        echo(f"[lead] {line}")
                text = getattr(msg, "content", "")
                if isinstance(text, list):
                    text = " ".join(p.get("text", "") for p in text if isinstance(p, dict))
                if getattr(msg, "type", "") == "ai" and text and not calls:
                    final = text
    report = store.case_dir(case_id) / "report.md"
    store.log(case_id, "lead", "lead investigator finished")
    return {"answer": final, "steps": steps, "report": report.read_text() if report.exists() else None}
