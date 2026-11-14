"""Case store: one folder per case holding its images, tasks, findings and timeline.

Everything is plain JSON so an investigator (or a teammate) can read it, diff it
and re-run any step. Findings are replaced per agent and image, which makes
every examiner safe to run again.
"""
from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from zoneinfo import ZoneInfo

from .models import Finding, now_iso, to_iso

_LOCK = threading.Lock()


@dataclass
class ImageRef:
    id: str                 # short key used in entity ids, e.g. "rm2"
    path: str               # where the image file lives
    label: str              # how to name it for people, e.g. "USB stick RM#2"
    kind: str = "usb"       # usb | optical | computer
    sha1_expected: str = ""
    sha1_actual: str = ""
    notes: str = ""

    @property
    def name(self) -> str:
        return Path(self.path).name

    def exists(self) -> bool:
        return Path(self.path).exists()


@dataclass
class Case:
    id: str
    name: str
    timezone: str = "America/New_York"
    description: str = ""
    images: list[ImageRef] = field(default_factory=list)
    created: str = field(default_factory=now_iso)
    people: list[dict] = field(default_factory=list)
    reference: str = ""          # name of an answer key in eval/, used for scoring only
    synthetic: bool = False      # True for generated practice cases

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    def local_to_iso(self, naive: Optional[datetime]) -> Optional[str]:
        """FAT and UDF store wall-clock time. Interpret it in the case timezone."""
        if naive is None:
            return None
        return to_iso(naive.replace(tzinfo=self.tz))

    def image(self, image_id: str) -> Optional[ImageRef]:
        for im in self.images:
            if im.id == image_id:
                return im
        return None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "timezone": self.timezone,
            "description": self.description,
            "created": self.created,
            "people": self.people,
            "reference": self.reference,
            "synthetic": self.synthetic,
            "images": [vars(i) | {"present": i.exists()} for i in self.images],
        }


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "case"


class CaseStore:
    def __init__(self, root: str | Path = "cases"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # -- cases ---------------------------------------------------------
    def case_dir(self, case_id: str) -> Path:
        return self.root / case_id

    def list_cases(self) -> list[dict]:
        out = []
        for p in sorted(self.root.glob("*/case.json")):
            try:
                d = json.loads(p.read_text())
                d["finding_count"] = len(self.load_findings(d["id"]))
                out.append(d)
            except Exception:
                continue
        return out

    def save_case(self, case: Case) -> None:
        d = self.case_dir(case.id)
        d.mkdir(parents=True, exist_ok=True)
        data = case.to_dict()
        for im in data["images"]:
            im.pop("present", None)
        self._write(d / "case.json", data)

    def load_case(self, case_id: str) -> Case:
        d = json.loads((self.case_dir(case_id) / "case.json").read_text())
        images = [ImageRef(**{k: v for k, v in im.items() if k != "present"}) for im in d.get("images", [])]
        return Case(
            id=d["id"], name=d["name"], timezone=d.get("timezone", "America/New_York"),
            description=d.get("description", ""), images=images,
            created=d.get("created", now_iso()), people=d.get("people", []),
            reference=d.get("reference", ""), synthetic=d.get("synthetic", False),
        )

    def recovered_dir(self, case_id: str, image_id: str) -> Path:
        d = self.case_dir(case_id) / "recovered" / image_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    # -- findings ------------------------------------------------------
    def load_findings(self, case_id: str) -> list[dict]:
        p = self.case_dir(case_id) / "findings.json"
        if not p.exists():
            return []
        return json.loads(p.read_text())

    def replace_findings(self, case_id: str, agent: str, image_id: Optional[str],
                         findings: list[Finding]) -> int:
        """Swap in this agent's findings for one image (or all, if image_id is None)."""
        with _LOCK:
            existing = self.load_findings(case_id)
            kept = [
                f for f in existing
                if not (f.get("agent") == agent and (image_id is None or f.get("data", {}).get("image_id") == image_id))
            ]
            new = []
            seen = {f["id"] for f in kept}
            for f in findings:
                if image_id is not None:
                    f.data.setdefault("image_id", image_id)
                d = f.to_dict()
                if d["id"] in seen:
                    continue
                seen.add(d["id"])
                new.append(d)
            self._write(self.case_dir(case_id) / "findings.json", kept + new)
            return len(new)

    # -- tasks (agent dispatch log) -----------------------------------
    def load_tasks(self, case_id: str) -> list[dict]:
        p = self.case_dir(case_id) / "tasks.json"
        return json.loads(p.read_text()) if p.exists() else []

    def upsert_task(self, case_id: str, task: dict) -> dict:
        with _LOCK:
            tasks = self.load_tasks(case_id)
            for i, t in enumerate(tasks):
                if t["id"] == task["id"]:
                    tasks[i] = {**t, **task}
                    break
            else:
                tasks.append(task)
            self._write(self.case_dir(case_id) / "tasks.json", tasks)
            return task

    def log(self, case_id: str, agent: str, message: str) -> None:
        """Append a line to the case activity log (streamed to the UI)."""
        with _LOCK:
            p = self.case_dir(case_id) / "activity.jsonl"
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open("a") as f:
                f.write(json.dumps({"t": now_iso(), "agent": agent, "message": message}) + "\n")

    def read_log(self, case_id: str, since: int = 0) -> list[dict]:
        p = self.case_dir(case_id) / "activity.jsonl"
        if not p.exists():
            return []
        lines = p.read_text().splitlines()
        return [json.loads(x) for x in lines[since:] if x.strip()]

    # -- timeline / score ---------------------------------------------
    def save_json(self, case_id: str, name: str, data: Any) -> None:
        self._write(self.case_dir(case_id) / name, data)

    def load_json(self, case_id: str, name: str, default: Any = None) -> Any:
        p = self.case_dir(case_id) / name
        return json.loads(p.read_text()) if p.exists() else default

    @staticmethod
    def _write(path: Path, data: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False))
        tmp.replace(path)
