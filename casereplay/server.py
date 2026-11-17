"""Case Replay web app: case tracking, agent dispatch, timeline and evidence API."""
from __future__ import annotations

import html
import os
import threading
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import agents, consensus, pipeline, score
from .ledger import Case, CaseStore, ImageRef, slug
from .models import now_iso

WEB = Path(__file__).resolve().parent.parent / "web"


class DispatchBody(BaseModel):
    agents: Optional[list[str]] = None
    images: Optional[list[str]] = None


class ReviewBody(BaseModel):
    finding_id: str
    status: str                      # confirmed | rejected | unreviewed
    note: str = ""


class AskBody(BaseModel):
    question: str = ""


class ImageBody(BaseModel):
    id: str
    path: str
    label: str
    kind: str = "usb"
    sha1_expected: str = ""


class CaseBody(BaseModel):
    name: str
    timezone: str = "America/New_York"
    description: str = ""
    images: list[ImageBody] = []


def create_app(store_root: str | Path = "cases") -> FastAPI:
    store = CaseStore(store_root)
    app = FastAPI(title="Case Replay", version="0.1.0")
    running: dict[str, str] = {}
    lock = threading.Lock()

    def case_or_404(case_id: str) -> Case:
        try:
            return store.load_case(case_id)
        except FileNotFoundError:
            raise HTTPException(404, f"no case {case_id}")

    def start(case_id: str, what: str, fn) -> None:
        with lock:
            if case_id in running:
                raise HTTPException(409, f"{running[case_id]} is still running on this case")
            running[case_id] = what

        def work() -> None:
            try:
                fn()
            except Exception as exc:                      # surfaced in the activity log
                store.log(case_id, "dispatch", f"stopped: {type(exc).__name__}: {exc}")
            finally:
                with lock:
                    running.pop(case_id, None)

        threading.Thread(target=work, daemon=True).start()

    @app.get("/api/meta")
    def meta() -> dict:
        return {"agents": pipeline.AGENTS, "order": pipeline.ORDER, "llm": agents.llm_available(),
                "model": agents.model_name(), "version": "0.1.0"}

    @app.get("/api/cases")
    def cases() -> list[dict]:
        return store.list_cases()

    @app.post("/api/cases")
    def new_case(body: CaseBody) -> dict:
        cid = slug(body.name)
        if (store.case_dir(cid) / "case.json").exists():
            raise HTTPException(409, "a case with this name already exists")
        case = Case(id=cid, name=body.name, timezone=body.timezone, description=body.description,
                    images=[ImageRef(i.id, i.path, i.label, i.kind, i.sha1_expected) for i in body.images])
        store.save_case(case)
        return case.to_dict()

    @app.get("/api/cases/{case_id}")
    def get_case(case_id: str) -> dict:
        case = case_or_404(case_id)
        return {**case.to_dict(), "tasks": store.load_tasks(case_id), "running": running.get(case_id)}

    @app.post("/api/cases/{case_id}/dispatch")
    def dispatch(case_id: str, body: DispatchBody) -> dict:
        case_or_404(case_id)
        names = ", ".join(body.agents) if body.agents else "all agents"
        store.log(case_id, "dispatch", f"sent out: {names}"
                  + (f" on {', '.join(body.images)}" if body.images else ""))
        start(case_id, names, lambda: pipeline.dispatch(store, case_id, body.agents, body.images))
        return {"started": True, "agents": body.agents or pipeline.ORDER}

    @app.get("/api/cases/{case_id}/status")
    def status(case_id: str, since: int = 0) -> dict:
        case_or_404(case_id)
        log = store.read_log(case_id, since)
        return {"running": running.get(case_id), "tasks": store.load_tasks(case_id), "log": log,
                "next": since + len(log), "findings": len(store.load_findings(case_id))}

    @app.get("/api/cases/{case_id}/timeline")
    def timeline(case_id: str) -> dict:
        case = case_or_404(case_id)
        tl = consensus.build(case, store)
        ref = score.load_reference(case.reference) if case.reference else None
        if ref:
            tl["score"] = score.score(case, store, ref)
            tl["reference"] = {"name": ref["name"], "source": ref.get("source"), "note": ref.get("note"),
                               "events": score.reference_events(ref, case.timezone)}
        report = store.case_dir(case_id) / "report.md"
        tl["report"] = report.read_text() if report.exists() else None
        tl["lead"] = store.load_json(case_id, "lead.json")
        return tl

    @app.post("/api/cases/{case_id}/review")
    def review(case_id: str, body: ReviewBody) -> dict:
        case_or_404(case_id)
        if body.status not in ("confirmed", "rejected", "unreviewed"):
            raise HTTPException(400, "status must be confirmed, rejected or unreviewed")
        if not any(f["id"] == body.finding_id for f in store.load_findings(case_id)):
            raise HTTPException(404, "no such finding")
        reviews = store.load_json(case_id, "reviews.json", {}) or {}
        reviews[body.finding_id] = {"status": body.status, "note": body.note, "at": now_iso()}
        store.save_json(case_id, "reviews.json", reviews)
        store.log(case_id, "reviewer", f"{body.finding_id} marked {body.status}")
        return reviews[body.finding_id]

    @app.get("/api/cases/{case_id}/recovered/{finding_id}")
    def recovered(case_id: str, finding_id: str):
        case_or_404(case_id)
        root = (store.case_dir(case_id) / "recovered").resolve()
        for f in store.load_findings(case_id):
            if f["id"] != finding_id:
                continue
            for e in f["evidence"]:
                rel = e.get("extracted_to")
                if not rel:
                    continue
                p = (store.case_dir(case_id) / rel).resolve()      # stored relative to the case folder
                if p.is_relative_to(root) and p.exists():
                    return FileResponse(p, filename=f["data"].get("name") or p.name,
                                        media_type="application/octet-stream")
        raise HTTPException(404, "no recovered file for this finding")

    @app.get("/api/cases/{case_id}/report")
    def report(case_id: str, format: str = "md"):
        case = case_or_404(case_id)
        tl = consensus.build(case, store)
        p = store.case_dir(case_id) / "report.md"
        text = p.read_text() if p.exists() else consensus.narrative(tl)
        if format == "html":
            by = (f"Narrative written by the lead investigator agent ({agents.model_name() or 'LLM'}) and checked "
                  "against the ledger." if p.exists() else "Narrative assembled from the agreed timeline without a language model.")
            return HTMLResponse(consensus.report_html(tl, text, by))
        return PlainTextResponse(text)

    @app.post("/api/cases/{case_id}/ask")
    def ask(case_id: str, body: AskBody) -> dict:
        case_or_404(case_id)
        if not agents.llm_available():
            raise HTTPException(400, "No model is configured. Set ANTHROPIC_API_KEY or CASEREPLAY_MODEL "
                                     "and restart. The agents still run without it.")

        def work() -> None:
            out = agents.investigate(case_id, store, body.question)
            store.save_json(case_id, "lead.json", {**out, "question": body.question, "at": now_iso(),
                                                   "model": agents.model_name()})

        start(case_id, "lead investigator", work)
        return {"started": True, "model": agents.model_name()}

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (WEB / "index.html").read_text()

    app.mount("/static", StaticFiles(directory=str(WEB)), name="static")
    return app


app = create_app(os.environ.get("CASE_REPLAY_CASES", "cases"))
