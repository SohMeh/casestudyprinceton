"""The deep agent layer, driven by a scripted model so the test needs no API key."""
import json
from pathlib import Path

import pytest
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage

from casereplay import agents, pipeline, synth
from casereplay.ledger import CaseStore


class Scripted(FakeMessagesListChatModel):
    def bind_tools(self, tools, **kwargs):
        return self


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    root = tmp_path_factory.mktemp("case")
    store = CaseStore(root / "cases")
    c = synth.build_practice_case(store, root / "data")
    return store, c


def test_pipeline_end_to_end(case):
    store, c = case
    tasks = pipeline.dispatch(store, c.id)
    assert all(t["status"] == "done" for t in tasks), [t for t in tasks if t["status"] != "done"]
    f = store.load_findings(c.id)
    kinds = {x["kind"] for x in f}
    assert {"deleted_file_recovered", "disguised_file", "volume_formatted", "wiping_tool", "evidence_link",
            "carved_file", "file_listed"} <= kinds
    assert all(x["evidence"] for x in f), "every finding carries an evidence pointer"
    tl = store.load_json(c.id, "timeline.json")
    full = [j for j in tl["journeys"] if len(j["devices"]) == 3]
    assert len(full) == 4                      # four documents seen on all three media
    assert all(j["true_name"].startswith("kestrel_") for j in full)
    fm = [x for x in f if x["kind"] == "volume_formatted"][0]
    assert fm["data"]["time_precise"] and fm["time"].startswith("2025-09-16T21:02")   # 17:02 local, in UTC


def test_tools_guard_citations(case):
    store, c = case
    tools = agents.make_tools(c.id, store)
    assert json.loads(tools["write_report"]("Nothing cited."))["saved"] is False
    assert json.loads(tools["write_report"]("Made up [f_000000000000]."))["unknown_ids"] == ["f_000000000000"]
    real = store.load_findings(c.id)[0]["id"]
    assert json.loads(tools["write_report"](f"Grounded claim [{real}]."))["saved"] is True
    bad = json.loads(tools["record_inference"]("x", "y", ["f_ffffffffffff"]))
    assert "error" in bad
    ok = json.loads(tools["record_inference"]("Linked events", "Because.", [real]))
    assert ok["status"] == "awaiting human review"


def test_deep_agent_runs_with_tools(case):
    store, c = case
    script = [
        AIMessage(content="", tool_calls=[{"name": "list_evidence", "args": {}, "id": "c1"}]),
        AIMessage(content="", tool_calls=[{"name": "run_examiner", "args": {"agent": "wiper", "image_id": "usb2"}, "id": "c2"}]),
        AIMessage(content="The personal stick was quick-formatted."),
    ]
    out = agents.investigate(c.id, store, "Was anything wiped?", model=Scripted(responses=script))
    assert "quick-formatted" in out["answer"]
    log = " ".join(x["message"] for x in store.read_log(c.id))
    assert "calls run_examiner (wiper)" in log
