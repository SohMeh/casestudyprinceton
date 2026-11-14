"""Identify what a file really is from its bytes, and compare that with its name.

This is the cheap, deterministic check behind the "disguised file" examiner.
No model is involved: a file named landscape.png that starts with a ZIP header
and contains word/document.xml is a Word document, whatever the name says.
"""
from __future__ import annotations

import io
import zipfile
from typing import Optional

OLE2_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")

# (label, family, signature bytes, offset)
SIGNATURES = [
    ("OLE2", "office", OLE2_MAGIC, 0),
    ("ZIP", "archive", b"PK\x03\x04", 0),
    ("JPEG", "image", b"\xff\xd8\xff", 0),
    ("PNG", "image", b"\x89PNG\r\n\x1a\n", 0),
    ("GIF", "image", b"GIF87a", 0),
    ("GIF", "image", b"GIF89a", 0),
    ("PDF", "document", b"%PDF-", 0),
    ("7Z", "archive", b"7z\xbc\xaf\x27\x1c", 0),
    ("RAR", "archive", b"Rar!\x1a\x07", 0),
    ("SQLITE", "database", b"SQLite format 3\x00", 0),
    ("AMR", "audio", b"#!AMR", 0),
    ("MP3", "audio", b"ID3", 0),
    ("RIFF", "media", b"RIFF", 0),
    ("MP4", "video", b"ftyp", 4),
    ("ONENOTE", "document", bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3"), 0),
    ("EXE", "program", b"MZ", 0),
    ("BMP", "image", b"BM", 0),
]

# What each extension is supposed to contain.
EXT_EXPECT = {
    "png": {"PNG"}, "jpg": {"JPEG"}, "jpeg": {"JPEG"}, "gif": {"GIF"}, "bmp": {"BMP"},
    "pdf": {"PDF"}, "7z": {"7Z"}, "rar": {"RAR"}, "zip": {"ZIP"},
    "db": {"SQLITE"}, "sqlite": {"SQLITE"},
    "amr": {"AMR"}, "mp3": {"MP3"}, "avi": {"RIFF"}, "wav": {"RIFF"}, "mp4": {"MP4"}, "mov": {"MP4"},
    "one": {"ONENOTE"}, "exe": {"EXE"}, "dll": {"EXE"},
    "doc": {"DOC", "OLE2"}, "xls": {"XLS", "OLE2"}, "ppt": {"PPT", "OLE2"},
    "docx": {"DOCX"}, "xlsx": {"XLSX"}, "pptx": {"PPTX"},
    "txt": {"TEXT"}, "svg": {"TEXT"}, "xml": {"TEXT"}, "csv": {"TEXT"}, "ini": {"TEXT"}, "log": {"TEXT"},
}

OFFICE_TYPES = {"DOC", "XLS", "PPT", "DOCX", "XLSX", "PPTX", "OLE2"}

# UTF-16LE stream names that identify the kind of OLE2 document.
_OLE_STREAMS = [
    ("DOC", "WordDocument"),
    ("XLS", "Workbook"),
    ("XLS", "Book"),
    ("PPT", "PowerPoint Document"),
]


def _ole_subtype(data: bytes) -> str:
    for label, name in _OLE_STREAMS:
        if name.encode("utf-16-le") in data:
            return label
    return "OLE2"


def _zip_subtype(data: bytes) -> str:
    """OOXML documents are ZIP archives with a known member layout."""
    names: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
    except Exception:
        # Truncated archive: fall back to scanning for member names.
        for marker, label in ((b"word/", "DOCX"), (b"xl/", "XLSX"), (b"ppt/", "PPTX")):
            if marker in data[: 4 * 1024 * 1024]:
                return label
        return "ZIP"
    if any(n.startswith("word/") for n in names):
        return "DOCX"
    if any(n.startswith("xl/") for n in names):
        return "XLSX"
    if any(n.startswith("ppt/") for n in names):
        return "PPTX"
    return "ZIP"


def _looks_like_text(head: bytes) -> bool:
    if not head:
        return False
    sample = head[:2048]
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127 or b >= 128)
    return printable / len(sample) > 0.95


def sniff(data: bytes) -> str:
    """Return the true type label for these bytes ("DOCX", "JPEG", "UNKNOWN", ...)."""
    if not data:
        return "EMPTY"
    for label, _family, sig, off in SIGNATURES:
        if data[off: off + len(sig)] == sig:
            if label == "OLE2":
                return _ole_subtype(data)
            if label == "ZIP":
                return _zip_subtype(data)
            if label == "RIFF":
                return "RIFF"
            return label
    if _looks_like_text(data):
        return "TEXT"
    return "UNKNOWN"


def extension_of(name: str) -> str:
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[1].lower().strip()


def check_disguise(name: str, true_type: str) -> Optional[dict]:
    """Compare a file name with its true type.

    Returns None when they agree (or when nothing can be said), otherwise a
    dict describing the mismatch. Office documents hidden under another
    extension are rated most serious.
    """
    ext = extension_of(name)
    if not ext or true_type in ("EMPTY", "UNKNOWN"):
        return None
    expected = EXT_EXPECT.get(ext)
    if expected is None:
        # Unknown extension holding an office document is still worth flagging.
        if true_type in OFFICE_TYPES:
            return {"claimed": ext, "actual": true_type, "severity": 2,
                    "reason": f"Unrecognised extension .{ext} holds a {true_type} document"}
        return None
    if true_type in expected:
        return None
    # An OOXML document is a ZIP container, so ".zip" passes a shallow magic
    # check. Looking inside the container catches it.
    severity = 3 if true_type in OFFICE_TYPES else 2
    return {
        "claimed": ext,
        "actual": true_type,
        "severity": severity,
        "reason": f"Named .{ext} but the content is {true_type}",
    }
