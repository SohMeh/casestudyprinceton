"""Data model shared by every examiner, agent and view.

A Finding is one thing an examiner established. It always carries Evidence
pointers (which image, where in it, what hash) so an investigator can check it.
Findings that have a time become events on the timeline.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# Lanes on the timeline. Every finding kind maps to exactly one lane.
LANES = ["communication", "web", "devices", "files", "cloud", "coverup", "system"]

KIND_LANE = {
    "email": "communication",
    "web_search": "web",
    "web_visit": "web",
    "web_download": "web",
    "usb_connected": "devices",
    "cd_burned": "devices",
    "volume_formatted": "coverup",
    "file_created": "files",
    "file_copied": "files",
    "file_renamed": "files",
    "file_opened": "files",
    "file_listed": "files",
    "deleted_file_recovered": "files",
    "carved_file": "files",
    "disguised_file": "coverup",
    "file_deleted": "coverup",
    "recycle_bin": "coverup",
    "wiping_tool": "coverup",
    "file_wiped": "coverup",
    "program_installed": "system",
    "program_executed": "system",
    "program_uninstalled": "coverup",
    "cloud_activity": "cloud",
    "evidence_link": "files",
    "system_info": "system",
    "note": "system",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def to_iso(dt: Optional[datetime]) -> Optional[str]:
    """Store every time as ISO 8601 in UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Evidence:
    """Where a finding comes from. Enough to re-derive it from the image."""

    image: str                      # image file name
    source: str                     # human-readable locator, e.g. "FAT32 directory entry"
    path: Optional[str] = None      # path inside the image, if any
    offset: Optional[int] = None    # byte offset in the image
    length: Optional[int] = None    # byte length
    sha256: Optional[str] = None    # hash of recovered content
    extracted_to: Optional[str] = None  # where the recovered bytes were written
    detail: Optional[str] = None    # raw value, e.g. registry key or record text

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Entity:
    """A person, device, file, account or program that findings can share."""

    type: str   # person | device | file | account | program | location
    id: str     # stable key, e.g. "device:rm2" or "sha256:ab12..."
    label: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    kind: str
    title: str
    agent: str                                   # which examiner produced it
    summary: str = ""
    time: Optional[str] = None                   # ISO UTC
    time_end: Optional[str] = None
    time_source: Optional[str] = None            # e.g. "FAT created time (local)"
    entities: list[Entity] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 0.8                      # 0..1, set by the examiner
    severity: int = 1                            # 1 info, 2 notable, 3 key
    tags: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    id: str = ""
    created: str = field(default_factory=now_iso)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = self.make_id()

    @property
    def lane(self) -> str:
        return KIND_LANE.get(self.kind, "system")

    def make_id(self) -> str:
        ev = self.evidence[0] if self.evidence else None
        key = json.dumps(
            [
                self.kind,
                self.agent,
                self.title,
                self.time,
                ev.image if ev else None,
                ev.path if ev else None,
                ev.offset if ev else None,
            ],
            sort_keys=True,
        )
        return "f_" + hashlib.sha1(key.encode()).hexdigest()[:12]

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "lane": self.lane,
            "title": self.title,
            "summary": self.summary,
            "agent": self.agent,
            "time": self.time,
            "time_end": self.time_end,
            "time_source": self.time_source,
            "entities": [e.to_dict() for e in self.entities],
            "evidence": [e.to_dict() for e in self.evidence],
            "confidence": round(self.confidence, 3),
            "severity": self.severity,
            "tags": self.tags,
            "data": self.data,
            "created": self.created,
        }

    @staticmethod
    def from_dict(d: dict) -> "Finding":
        return Finding(
            kind=d["kind"],
            title=d["title"],
            agent=d.get("agent", "unknown"),
            summary=d.get("summary", ""),
            time=d.get("time"),
            time_end=d.get("time_end"),
            time_source=d.get("time_source"),
            entities=[Entity(**e) for e in d.get("entities", [])],
            evidence=[Evidence(**e) for e in d.get("evidence", [])],
            confidence=d.get("confidence", 0.8),
            severity=d.get("severity", 1),
            tags=d.get("tags", []),
            data=d.get("data", {}),
            id=d.get("id", ""),
            created=d.get("created", now_iso()),
        )


def file_entity(sha256: Optional[str], label: str) -> Entity:
    key = f"sha256:{sha256[:16]}" if sha256 else f"name:{label.lower()}"
    return Entity("file", key, label)


def device_entity(device_id: str, label: str) -> Entity:
    return Entity("device", f"device:{device_id}", label)
