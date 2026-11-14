"""Signature-based file carving.

When a file system no longer points at a file (deleted from a CD-R, or lost in
a format), the bytes are usually still on the medium. We look for known file
headers at sector boundaries and work out each file's true length from its own
internal structure, so nothing is guessed:

- OLE2 (doc, xls, ppt): length comes from the sector allocation table.
- ZIP and OOXML (docx, xlsx, pptx): length comes from the end-of-central-directory record.
- JPEG: we walk the marker segments to the end-of-image marker.
- PNG: we walk the chunks to IEND.
- PDF: we take the last %%EOF before the next header.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional

from .images import stream_size
from .magic import OLE2_MAGIC, sniff

ALIGN = 512                       # works for disks (512) and optical media (2048)
CHUNK = 16 * 1024 * 1024
MAX_FILE = 256 * 1024 * 1024

HEADERS = [
    (OLE2_MAGIC, "OLE2"),
    (b"PK\x03\x04", "ZIP"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"%PDF-", "PDF"),
]


@dataclass
class Carved:
    offset: int
    size: int
    type: str                     # true type from content, e.g. DOCX
    sha256: str
    complete: bool                # internal structure validated end to end
    note: str = ""


def _read(fh: BinaryIO, offset: int, size: int) -> bytes:
    fh.seek(offset)
    return fh.read(size)


# ---------------------------------------------------------------- OLE2
def ole2_size(fh: BinaryIO, start: int, limit: int) -> Optional[int]:
    """Length of an OLE2 compound file, from its FAT."""
    hdr = _read(fh, start, 512)
    if len(hdr) < 512 or hdr[:8] != OLE2_MAGIC:
        return None
    sector_shift = struct.unpack_from("<H", hdr, 30)[0]
    if sector_shift not in (9, 12):
        return None
    ssz = 1 << sector_shift
    n_fat = struct.unpack_from("<I", hdr, 44)[0]
    first_difat = struct.unpack_from("<I", hdr, 68)[0]
    n_difat = struct.unpack_from("<I", hdr, 72)[0]
    if n_fat == 0 or n_fat > 100000:
        return None

    def sector_off(sid: int) -> int:
        return start + (sid + 1) * ssz

    fat_sectors = [s for s in struct.unpack_from("<109I", hdr, 76) if s < 0xFFFFFFFA]
    # Large files chain extra DIFAT sectors.
    sid = first_difat
    for _ in range(min(n_difat, 4096)):
        if sid >= 0xFFFFFFFA:
            break
        blk = _read(fh, sector_off(sid), ssz)
        if len(blk) < ssz:
            break
        vals = struct.unpack_from(f"<{ssz // 4}I", blk, 0)
        fat_sectors.extend(s for s in vals[:-1] if s < 0xFFFFFFFA)
        sid = vals[-1]
    fat_sectors = fat_sectors[:n_fat]
    if not fat_sectors:
        return None

    per = ssz // 4
    last_used = -1
    for idx, fs in enumerate(fat_sectors):
        off = sector_off(fs)
        if off + ssz > limit:
            return None
        blk = _read(fh, off, ssz)
        if len(blk) < ssz:
            return None
        vals = struct.unpack_from(f"<{per}I", blk, 0)
        for j in range(per - 1, -1, -1):
            if vals[j] != 0xFFFFFFFF:       # anything but FREESECT is in use
                last_used = max(last_used, idx * per + j)
                break
    if last_used < 0:
        return None
    size = (last_used + 2) * ssz             # +1 for the header, +1 for index to count
    return size if 0 < size <= MAX_FILE else None


# ---------------------------------------------------------------- ZIP
def zip_size(fh: BinaryIO, start: int, limit: int) -> Optional[int]:
    """Length of a ZIP archive, from its end-of-central-directory record."""
    window = min(MAX_FILE, limit - start)
    pos = 0
    carry = b""
    while pos < window:
        block = _read(fh, start + pos, min(CHUNK, window - pos))
        if not block:
            break
        data = carry + block
        base = pos - len(carry)
        i = data.find(b"PK\x05\x06")
        while i >= 0:
            eocd = base + i
            rec = data[i: i + 22]
            if len(rec) < 22:
                rec = _read(fh, start + eocd, 22)
            if len(rec) == 22:
                cd_size, cd_off, comment = struct.unpack_from("<IIH", rec, 12)
                # In a contiguous archive the central directory ends exactly
                # where the end record begins.
                if cd_off + cd_size == eocd and _read(fh, start + cd_off, 4) == b"PK\x01\x02":
                    return eocd + 22 + comment
            i = data.find(b"PK\x05\x06", i + 1)
        carry = data[-21:]
        pos += len(block)
    return None


# ---------------------------------------------------------------- JPEG
def jpeg_size(fh: BinaryIO, start: int, limit: int) -> Optional[int]:
    window = min(64 * 1024 * 1024, limit - start)
    data = _read(fh, start, window)
    if data[:3] != b"\xff\xd8\xff":
        return None
    i = 2
    n = len(data)
    while i + 4 <= n:
        if data[i] != 0xFF:
            return None
        marker = data[i + 1]
        if marker == 0xD9:
            return i + 2
        if marker in (0x01,) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        seglen = struct.unpack_from(">H", data, i + 2)[0]
        if seglen < 2:
            return None
        i += 2 + seglen
        if marker == 0xDA:                   # start of scan: entropy-coded data follows
            while i + 1 < n:
                j = data.find(b"\xff", i)
                if j < 0 or j + 1 >= n:
                    return None
                nxt = data[j + 1]
                if nxt == 0x00 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                    i = j + 1 if nxt == 0xFF else j + 2
                    continue
                i = j
                break
            else:
                return None
    return None


# ---------------------------------------------------------------- PNG / PDF
def png_size(fh: BinaryIO, start: int, limit: int) -> Optional[int]:
    pos = start + 8
    for _ in range(200000):
        head = _read(fh, pos, 8)
        if len(head) < 8:
            return None
        length, ctype = struct.unpack(">I4s", head)
        if length > MAX_FILE or not ctype.isalpha():
            return None
        pos += 12 + length
        if ctype == b"IEND":
            return pos - start
        if pos > limit:
            return None
    return None


def pdf_size(fh: BinaryIO, start: int, limit: int) -> Optional[int]:
    window = min(MAX_FILE, limit - start)
    data = _read(fh, start, min(window, 64 * 1024 * 1024))
    nxt = data.find(b"%PDF-", 5)
    scope = data if nxt < 0 else data[:nxt]
    end = scope.rfind(b"%%EOF")
    if end < 0:
        return None
    return end + 5


SIZERS = {"OLE2": ole2_size, "ZIP": zip_size, "JPEG": jpeg_size, "PNG": png_size, "PDF": pdf_size}


def carve(fh: BinaryIO, start: int = 0, end: Optional[int] = None,
          skip: Optional[list[tuple[int, int]]] = None) -> Iterator[Carved]:
    """Yield every file whose header sits on a sector boundary in [start, end).

    `skip` lists byte ranges already accounted for (allocated files), so a
    live file is not reported a second time as "carved".
    """
    total = stream_size(fh)
    end = min(end or total, total)
    skip = sorted(skip or [])
    pos = start - (start % ALIGN)
    while pos < end:
        block = _read(fh, pos, min(CHUNK, end - pos))
        if not block:
            break
        jump_to = None
        for rel in range(0, len(block), ALIGN):
            head = block[rel: rel + 8]
            if len(head) < 8:
                break
            kind = None
            for sig, label in HEADERS:
                if head[: len(sig)] == sig:
                    kind = label
                    break
            if kind is None:
                continue
            abs_off = pos + rel
            if any(a <= abs_off < b for a, b in skip):
                continue
            size = SIZERS[kind](fh, abs_off, end)
            complete = size is not None
            if size is None:
                continue                       # header without a valid structure: not a file
            data = _read(fh, abs_off, size)
            true_type = sniff(data)
            yield Carved(
                offset=abs_off,
                size=size,
                type=true_type,
                sha256=hashlib.sha256(data).hexdigest(),
                complete=complete and len(data) == size,
            )
            jump_to = abs_off + size
            break
        if jump_to is not None:
            # Resume at the first sector boundary after the carved file.
            pos = jump_to + (-jump_to % ALIGN)
        else:
            pos += len(block)
