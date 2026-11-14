"""Command line: python -m casereplay <command>"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import agents, consensus, nist, pipeline, score, synth
from .ledger import CaseStore


def _serve(store_root: str, port: int) -> None:
    import uvicorn

    os.environ["CASE_REPLAY_CASES"] = store_root
    print(f"\nCase Replay is running at http://127.0.0.1:{port}\n")
    uvicorn.run("casereplay.server:app", host="127.0.0.1", port=port, log_level="warning")


def _print_score(result: dict) -> None:
    print(f"\nScore against: {result['reference']}")
    for c in result["checks"]:
        mark = "not run" if not c["ran"] else f"{c['found']}/{c['expected']}"
        print(f"  {mark:>8}  {c['label']}")
        if c["ran"] and c["missed"] and len(c["missed"]) <= 6:
            print(f"            missed: {', '.join(map(str, c['missed']))}")
    if result["overall"] is not None:
        print(f"  overall: {result['overall']:.0%} of checked items\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="casereplay", description="Case Replay: agent-driven forensic timelines")
    ap.add_argument("--cases", default=os.environ.get("CASE_REPLAY_CASES", "cases"), help="case store folder")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("demo", help="build the synthetic practice case, run every agent, open the app")
    p.add_argument("--data", default="data/practice")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--no-serve", action="store_true")

    p = sub.add_parser("start", help="practice case + NIST case (if downloaded), then the web app")
    p.add_argument("--data", default=os.environ.get("CASE_REPLAY_DATA", "data"))
    p.add_argument("--port", type=int, default=8000)

    p = sub.add_parser("nist", help="register the NIST Data Leakage Case from downloaded images")
    p.add_argument("--data", default=os.environ.get("CASE_REPLAY_DATA", "data"))
    p.add_argument("--run", action="store_true", help="run every agent right away")

    p = sub.add_parser("run", help="send agents out on a case")
    p.add_argument("case")
    p.add_argument("--agents", default="", help="comma list: " + ",".join(pipeline.ORDER))
    p.add_argument("--images", default="", help="comma list of image ids")

    p = sub.add_parser("lead", help="let the LLM lead investigator work the case (needs a model)")
    p.add_argument("case")
    p.add_argument("question", nargs="?", default="")

    p = sub.add_parser("score", help="score a case against its answer key")
    p.add_argument("case")
    p = sub.add_parser("report", help="print the narrative for a case")
    p.add_argument("case")
    p = sub.add_parser("serve", help="start the web app")
    p.add_argument("--port", type=int, default=8000)
    sub.add_parser("cases", help="list cases")

    a = ap.parse_args(argv)
    store = CaseStore(a.cases)

    if a.cmd == "demo":
        print("Building the synthetic practice case...")
        case = synth.build_practice_case(store, Path(a.data))
        pipeline.dispatch(store, case.id, echo=print)
        tl = consensus.build(case, store)
        print(f"\n{tl['stats']['findings']} findings, {tl['stats']['recovered']} files recovered, "
              f"{tl['stats']['disguised']} disguised files flagged.")
        if not a.no_serve:
            _serve(a.cases, a.port)
    elif a.cmd == "start":
        if not (store.case_dir(synth.CASE_ID) / "findings.json").exists():
            print("Building the synthetic practice case...")
            case = synth.build_practice_case(store, Path(a.data) / "practice")
            pipeline.dispatch(store, case.id, echo=print)
        case = nist.build_case(store, Path(a.data))
        have = [im.label for im in case.images if im.exists()]
        print(f"\nNIST case: {len(have)} of {len(case.images)} images found in {Path(a.data).resolve()}"
              + ("" if have else "  (download them with: bash scripts/fetch_dataset.sh --small)"))
        _serve(a.cases, a.port)
    elif a.cmd == "nist":
        case = nist.build_case(store, Path(a.data))
        for im in case.images:
            print(f"  {'found  ' if im.exists() else 'missing'}  {im.label:16} {im.path}")
        if a.run:
            pipeline.dispatch(store, case.id, echo=print)
            _print_score(score.score(case, store, score.load_reference(case.reference)))
        else:
            print(f"\nCase registered as '{case.id}'. Next: python -m casereplay run {case.id}")
    elif a.cmd == "run":
        tasks = pipeline.dispatch(store, a.case, [x for x in a.agents.split(",") if x] or None,
                                  [x for x in a.images.split(",") if x] or None, echo=print)
        for t in tasks:
            print(f"  {t['status']:6} {t['agent']:10} {t['image']:28} {t['findings']:5} findings  {t['seconds']}s"
                  + (f"  {t['error']}" if t["error"] else ""))
        case = store.load_case(a.case)
        if case.reference:
            _print_score(score.score(case, store, score.load_reference(case.reference)))
    elif a.cmd == "lead":
        if not agents.llm_available():
            print("No model configured. Set ANTHROPIC_API_KEY or CASEREPLAY_MODEL.", file=sys.stderr)
            return 2
        out = agents.investigate(a.case, store, a.question, echo=print)
        print("\n" + (out["report"] or out["answer"]))
    elif a.cmd == "score":
        case = store.load_case(a.case)
        if not case.reference:
            print("This case has no answer key.")
            return 1
        _print_score(score.score(case, store, score.load_reference(case.reference)))
    elif a.cmd == "report":
        case = store.load_case(a.case)
        print(consensus.narrative(consensus.build(case, store)))
    elif a.cmd == "serve":
        _serve(a.cases, a.port)
    elif a.cmd == "cases":
        print(json.dumps(store.list_cases(), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
