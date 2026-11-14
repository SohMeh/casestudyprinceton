"""Small helpers shared by examiners."""
from __future__ import annotations

import hashlib
import re
from typing import Optional

HEAD = 16384


def human(n: float) -> str:
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n} bytes"


def safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._()\[\]#-]+", "_", name).strip("_") or "file"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def head16(data: bytes) -> Optional[str]:
    """Hash of the first 16 KB. Lets us match a carved copy whose length is off
    by a few bytes against the original. None for files smaller than 16 KB."""
    if len(data) < HEAD:
        return None
    return hashlib.sha256(data[:HEAD]).hexdigest()
