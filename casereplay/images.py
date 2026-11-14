"""Open forensic images read-only and find the volumes inside them.

Supports EnCase E01 (single or multi-segment) and raw dd images. Pure Python,
so it runs the same on macOS, Linux and Windows.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional


def open_image(path: str | Path) -> BinaryIO:
    """Return a seekable, read-only stream over the image's sector data."""
    p = Path(path)
    if p.suffix.lower() in (".e01", ".ex01"):
        from dissect.evidence import ewf

        segments = sorted(ewf.find_files(p))
        handles = [seg.open("rb") for seg in segments]
        return ewf.EWF(handles).open()
    return p.open("rb")


def stream_size(fh: BinaryIO) -> int:
    size = getattr(fh, "size", None)
    if isinstance(size, int) and size > 0:
        return size
    pos = fh.tell()
    fh.seek(0, 2)
    end = fh.tell()
    fh.seek(pos)
    return end


def file_sha1(path: str | Path, chunk: int = 4 * 1024 * 1024) -> str:
    """SHA-1 of the image file as downloaded (what NIST publishes)."""
    h = hashlib.sha1()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest().upper()


@dataclass
class Volume:
    offset: int          # byte offset of the volume inside the image
    size: int            # bytes (0 when unknown)
    fstype: str          # FAT32 | EXFAT | NTFS | UDF | UNKNOWN
    label: str = ""


def _boot_fstype(boot: bytes) -> str:
    if len(boot) < 512:
        return "UNKNOWN"
    if boot[3:11] == b"EXFAT   ":
        return "EXFAT"
    if boot[3:11] == b"NTFS    ":
        return "NTFS"
    if boot[82:90] == b"FAT32   ":
        return "FAT32"
    if boot[54:59] in (b"FAT16", b"FAT12"):
        return "FAT16"
    return "UNKNOWN"


def _is_udf_or_iso(fh: BinaryIO) -> bool:
    """Optical images carry volume descriptors from sector 16 (2048 bytes each)."""
    try:
        for sector in range(16, 24):
            fh.seek(sector * 2048)
            d = fh.read(8)
            if d[1:6] in (b"CD001", b"BEA01", b"NSR02", b"NSR03", b"TEA01"):
                return True
    except Exception:
        return False
    return False


def find_volumes(fh: BinaryIO) -> list[Volume]:
    """Locate file systems: optical media, a bare boot sector, or MBR partitions."""
    total = stream_size(fh)
    fh.seek(0)
    sector0 = fh.read(512)
    vols: list[Volume] = []

    if _is_udf_or_iso(fh):
        return [Volume(0, total, "UDF")]

    fstype = _boot_fstype(sector0)
    if fstype != "UNKNOWN":
        return [Volume(0, total, fstype)]

    if sector0[510:512] == b"\x55\xaa":
        for i in range(4):
            entry = sector0[446 + i * 16: 462 + i * 16]
            ptype = entry[4]
            lba, nsect = struct.unpack("<II", entry[8:16])
            if ptype == 0 or nsect == 0:
                continue
            off = lba * 512
            if off >= total:
                continue
            fh.seek(off)
            vols.append(Volume(off, nsect * 512, _boot_fstype(fh.read(512))))
    return vols or [Volume(0, total, "UNKNOWN")]


class SubStream:
    """A window onto part of another stream (one volume inside a disk image)."""

    def __init__(self, fh: BinaryIO, offset: int, size: Optional[int] = None):
        self.fh = fh
        self.offset = offset
        self.size = size if size else stream_size(fh) - offset
        self.pos = 0

    def seek(self, pos: int, whence: int = 0) -> int:
        if whence == 0:
            self.pos = pos
        elif whence == 1:
            self.pos += pos
        else:
            self.pos = self.size + pos
        return self.pos

    def tell(self) -> int:
        return self.pos

    def read(self, n: int = -1) -> bytes:
        if n < 0 or self.pos + n > self.size:
            n = max(0, self.size - self.pos)
        self.fh.seek(self.offset + self.pos)
        data = self.fh.read(n)
        self.pos += len(data)
        return data
