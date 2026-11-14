"""Dispatch: send agents out on a case and track each task.

Every agent here is a deterministic examiner. The same functions are exposed
as tools to the LLM lead investigator in agents.py, so a run with or without
a model produces the same evidence. Only the planning and the prose differ.
"""
from __future__ import annotations

import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

from . import consensus
from .examiners import activity, disguise, inventory, recovery, wipers
from .ledger import Case, CaseStore, ImageRef
from .models import now_iso

AGENTS = {
    "inventory": {"label": "Intake", "verb": "Verify images and list live files", "scope": "image",
                  "does": "Checks each image against its published hash, finds the volumes and lists every "
                          "file the file system still shows, with its hash and true type."},
    "recovery": {"label": "Recovery", "verb": "Recover deleted files", "scope": "image",
                 "does": "Rebuilds files from directory entries that survived a delete or a format, reads old "
                         "disc directories, and carves files that have no entry left."},
    "activity": {"label": "Activity", "verb": "Reconstruct computer activity", "scope": "image",
                 "does": "Reads USB history, searches, downloads, program runs, installs, the Recycle Bin and "
                         "the NTFS change journal from the computer image."},
    "disguise": {"label": "Disguise", "verb": "Catch files under false names", "scope": "case",
                 "does": "Compares every file name with the file's real content and matches identical "
                         "content across devices to reveal the original name."},
    "wiper": {"label": "Wiper", "verb": "Flag wiping and formatting", "scope": "image",
              "does": "Detects quick formats on media and traces of erasers and cleaners on the computer."},
    "consensus": {"label": "Consensus", "verb": "Build the agreed timeline", "scope": "case",
                  "does": "Puts every finding on one clock, groups them into story beats, follows each file "
                          "across devices and lists what does not add up."},
}
ORDER = ["inventory", "recovery", "activity", "disguise", "wiper", "consensus"]
PREREQ = {"disguise": ["inventory", "recovery"], "wiper": ["activity"]}
_RUN = {"inventory": inventory.run, "recovery": recovery.run, "activity": activity.run, "wiper": wipers.run}


def _applies(agent: str, image: ImageRef) -> bool:
    if agent == "activity":
        return image.kind in ("computer", "triage")
    if agent in ("recovery",):
        return image.kind not in ("computer", "triage")
    if agent == "inventory":
        return image.kind != "triage"
    if agent == "wiper":
        return True
    return True


def run_task(store: CaseStore, case: Case, agent: str, image: Optional[ImageRef] = None,
             echo: Optional[Callable[[str], None]] = None) -> dict:
    task = {"id": "t_" + uuid.uuid4().hex[:8], "agent": agent, "image_id": image.id if image else None,
            "image": image.label if image else "whole case", "status": "running", "started": now_iso(),
            "findings": 0, "error": None, "seconds": None}
    store.upsert_task(case.id, task)

    def log(msg: str) -> None:
        store.log(case.id, agent, msg)
        if echo:
            echo(f"[{agent}] {msg}")

    t0 = time.time()
    try:
        if agent == "consensus":
            tl = consensus.build(case, store)
            task["findings"] = tl["stats"]["beats"]
            log(f"timeline built: {tl['stats']['timed']} dated findings in {tl['stats']['beats']} beats, "
                f"{tl['stats']['journeys']} file identities, {len(tl['cautions'])} open points")
        elif agent == "disguise":
            found = disguise.run_case(case, store, log)
            task["findings"] = store.replace_findings(case.id, agent, None, found)
        else:
            if image is None:
                raise ValueError(f"{agent} needs an image")
            if not image.exists():
                raise FileNotFoundError(f"{image.name} is not on disk yet")
            found = _RUN[agent](case, store, image, log)
            task["findings"] = store.replace_findings(case.id, agent, image.id, found)
        task["status"] = "done"
    except Exception as exc:
        task["status"] = "failed"
        task["error"] = f"{type(exc).__name__}: {exc}"
        log(f"failed: {task['error']}")
        store.log(case.id, agent, traceback.format_exc(limit=3).strip().splitlines()[-1])
    task["seconds"] = round(time.time() - t0, 2)
    task["finished"] = now_iso()
    store.upsert_task(case.id, task)
    return task


def dispatch(store: CaseStore, case_id: str, agents: Optional[list[str]] = None,
             images: Optional[list[str]] = None, echo: Optional[Callable[[str], None]] = None) -> list[dict]:
    """Run the chosen agents (default: all) on the chosen images (default: all present)."""
    case = store.load_case(case_id)
    wanted = [a for a in ORDER if a in (agents or ORDER)]
    done_before = {(t["agent"], t["image_id"]) for t in store.load_tasks(case_id) if t["status"] == "done"}
    targets = [im for im in case.images if (not images or im.id in images)]
    present = [im for im in targets if im.exists()]
    for im in targets:
        if not im.exists():
            store.log(case_id, "dispatch", f"{im.label}: image file not found at {im.path}, skipped")
    # Pull in prerequisites that have never run for these images.
    for a in list(wanted):
        for pre in PREREQ.get(a, []):
            if pre not in wanted and any((pre, im.id) not in done_before and _applies(pre, im) for im in present):
                wanted.append(pre)
    if "consensus" not in wanted:
        wanted.append("consensus")
    wanted = [a for a in ORDER if a in wanted]

    results: list[dict] = []
    for agent in wanted:
        if AGENTS[agent]["scope"] == "case":
            results.append(run_task(store, case, agent, None, echo))
            continue
        todo = [im for im in present if _applies(agent, im)]
        if not todo:
            continue
        with ThreadPoolExecutor(max_workers=min(3, len(todo))) as pool:
            results += list(pool.map(lambda im: run_task(store, case, agent, im, echo), todo))
        case = store.load_case(case_id)        # intake may have stored verified hashes
    return results
