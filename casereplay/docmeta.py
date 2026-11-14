"""Light metadata from recovered office documents.

A carved file has no name, but the document inside often says what it is:
a title, an author, the first line of text and its own saved-at times. These
help an investigator name the file and tie it to a person.
"""
from __future__ import annotations

import io
import re
import zipfile
from typing import Any, Optional

_TAG = re.compile(r"<[^>]+>")


def _first_text(xml: str, tag: str, limit: int = 160) -> str:
    parts = re.findall(rf"<{tag}(?:\s[^>]*)?>([^<]*)</{tag}>", xml)
    text = " ".join(p.strip() for p in parts if p.strip())
    return re.sub(r"\s+", " ", text)[:limit]


def _core(xml: str, name: str) -> Optional[str]:
    m = re.search(rf"<(?:\w+:)?{name}(?:\s[^>]*)?>([^<]*)</(?:\w+:)?{name}>", xml)
    return m.group(1).strip() if m and m.group(1).strip() else None


def ooxml_meta(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return out
    names = set(z.namelist())

    def read(name: str) -> str:
        try:
            return z.read(name).decode("utf-8", "replace")
        except Exception:
            return ""

    if "docProps/core.xml" in names:
        core = read("docProps/core.xml")
        for key, tag in (("title", "title"), ("author", "creator"), ("last_saved_by", "lastModifiedBy"),
                         ("doc_created", "created"), ("doc_modified", "modified")):
            val = _core(core, tag)
            if val:
                out[key] = val
    if "word/document.xml" in names:
        out["first_text"] = _first_text(read("word/document.xml"), "w:t")
    elif "ppt/slides/slide1.xml" in names:
        out["first_text"] = _first_text(read("ppt/slides/slide1.xml"), "a:t")
    elif "xl/sharedStrings.xml" in names:
        out["first_text"] = _first_text(read("xl/sharedStrings.xml"), "t")
    return {k: v for k, v in out.items() if v}


def ole_meta(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    try:
        import olefile

        ole = olefile.OleFileIO(io.BytesIO(data))
        meta = ole.get_metadata()

        def text(v: Any) -> Optional[str]:
            if v is None:
                return None
            if isinstance(v, bytes):
                v = v.decode("utf-8", "replace")
            v = str(v).strip().strip("\x00")
            return v or None

        for key, attr in (("title", "title"), ("author", "author"), ("last_saved_by", "last_saved_by"),
                          ("doc_created", "create_time"), ("doc_modified", "last_saved_time")):
            val = text(getattr(meta, attr, None))
            if val:
                out[key] = val
        ole.close()
    except Exception:
        pass
    return out


def document_meta(data: bytes, true_type: str) -> dict[str, Any]:
    if true_type in ("DOCX", "XLSX", "PPTX"):
        return ooxml_meta(data)
    if true_type in ("DOC", "XLS", "PPT", "OLE2"):
        return ole_meta(data)
    return {}
