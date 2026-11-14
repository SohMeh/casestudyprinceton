"""Best-effort UDF scanner for write-once discs.

A CD-R cannot overwrite anything. When a file is "deleted", the disc gets a new
directory that leaves the file out, but the old directory blocks and the file
data stay on the disc. We scan every sector for UDF descriptors with a valid
tag checksum and collect:

- File Identifier Descriptors (names, and whether an entry is flagged deleted)
- File Entries (size and timestamps)

A name that appears in an older directory version but not in the newest one is
a file the user removed from view.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import BinaryIO, Optional

from .images import stream_size

SECTOR = 2048
TAG_FID = 257
TAG_FE = 261
TAG_EFE = 266
TAG_PD = 5


@dataclass
class UdfName:
    name: str
    sector: int                 # sector of the directory block holding this entry
    deleted_flag: bool
    is_dir: bool
    is_parent: bool
    icb_block: int              # logical block of the file's File Entry


@dataclass
class UdfFile:
    sector: int                 # sector where the File Entry was found
    tag_location: int           # its logical block number inside the partition
    file_type: int              # 4 directory, 5 regular file
    size: int
    modified: Optional[datetime]
    accessed: Optional[datetime]
    created: Optional[datetime]
    extents: list[tuple[int, int]] = field(default_factory=list)   # (logical block, length)
    names: list[UdfName] = field(default_factory=list)


def _tag_ok(block: bytes) -> Optional[int]:
    if len(block) < 16:
        return None
    ident = struct.unpack_from("<H", block, 0)[0]
    if ident not in (TAG_FID, TAG_FE, TAG_EFE, TAG_PD):
        return None
    checksum = (sum(block[0:4]) + sum(block[5:16])) & 0xFF
    if checksum != block[4]:
        return None
    return ident


def _timestamp(raw: bytes) -> Optional[datetime]:
    if len(raw) < 12:
        return None
    tz_field, year, month, day, hour, minute, second = struct.unpack_from("<HhBBBBB", raw, 0)
    if year < 1980 or not (1 <= month <= 12) or not (1 <= day <= 31):
        return None
    offset = tz_field & 0x0FFF
    if offset & 0x800:
        offset -= 0x1000
    try:
        dt = datetime(year, month, day, hour, minute, min(second, 59))
    except ValueError:
        return None
    if (tz_field >> 12) == 1 and offset != -2047:
        dt = dt.replace(tzinfo=timezone(timedelta(minutes=offset)))
    return dt


def _dstring(raw: bytes) -> str:
    if not raw:
        return ""
    comp = raw[0]
    body = raw[1:]
    if comp == 16:
        return body.decode("utf-16-be", "replace")
    return body.decode("latin-1", "replace")


def parse_fids(data: bytes, sector: int) -> list[UdfName]:
    """Parse consecutive File Identifier Descriptors from a directory buffer."""
    out: list[UdfName] = []
    pos = 0
    while pos + 38 <= len(data):
        if _tag_ok(data[pos: pos + 16]) != TAG_FID:
            break
        chars = data[pos + 18]
        l_fi = data[pos + 19]
        icb_block = struct.unpack_from("<I", data, pos + 24)[0]
        l_iu = struct.unpack_from("<H", data, pos + 36)[0]
        name_off = pos + 38 + l_iu
        name = _dstring(data[name_off: name_off + l_fi])
        out.append(UdfName(
            name=name, sector=sector, deleted_flag=bool(chars & 0x04), is_dir=bool(chars & 0x02),
            is_parent=bool(chars & 0x08), icb_block=icb_block,
        ))
        length = 38 + l_iu + l_fi
        pos += length + (-length % 4)
    return out


def parse_file_entry(block: bytes, sector: int, ident: int) -> Optional[tuple[UdfFile, list[UdfName]]]:
    try:
        tag_location = struct.unpack_from("<I", block, 12)[0]
        file_type = block[27]
        flags = struct.unpack_from("<H", block, 34)[0]
        size = struct.unpack_from("<Q", block, 56)[0]
        if ident == TAG_FE:
            accessed, modified, created = _timestamp(block[72:84]), _timestamp(block[84:96]), None
            l_ea, l_ad = struct.unpack_from("<II", block, 168)
            ad_off = 176 + l_ea
        else:
            accessed, modified = _timestamp(block[80:92]), _timestamp(block[92:104])
            created = _timestamp(block[104:116])
            l_ea, l_ad = struct.unpack_from("<II", block, 208)
            ad_off = 216 + l_ea
    except struct.error:
        return None
    if file_type not in (4, 5) or size > (1 << 40) or ad_off + l_ad > len(block) + SECTOR * 4:
        return None
    f = UdfFile(sector=sector, tag_location=tag_location, file_type=file_type, size=size,
                modified=modified, accessed=accessed, created=created)
    ads = block[ad_off: ad_off + l_ad]
    ad_type = flags & 0x07
    inline_names: list[UdfName] = []
    if ad_type == 0:                                   # short allocation descriptors
        for i in range(0, len(ads) - 7, 8):
            length, pos = struct.unpack_from("<II", ads, i)
            if length & 0x3FFFFFFF:
                f.extents.append((pos, length & 0x3FFFFFFF))
    elif ad_type == 1:                                 # long allocation descriptors
        for i in range(0, len(ads) - 15, 16):
            length, pos = struct.unpack_from("<II", ads, i)
            if length & 0x3FFFFFFF:
                f.extents.append((pos, length & 0x3FFFFFFF))
    elif ad_type == 3 and file_type == 4:              # directory stored inside the entry
        inline_names = parse_fids(ads, sector)
    return f, inline_names


@dataclass
class UdfScan:
    partition_start: int = 0
    files: list[UdfFile] = field(default_factory=list)
    names: list[UdfName] = field(default_factory=list)

    def latest_directory_sector(self) -> int:
        parents = [n.sector for n in self.names if n.is_parent]
        return max(parents) if parents else -1

    def visible_names(self) -> set[str]:
        last = self.latest_directory_sector()
        return {n.name for n in self.names
                if n.sector == last and not n.is_parent and not n.deleted_flag}

    def hidden_names(self) -> list[UdfName]:
        """Names seen in any directory version that the newest one no longer shows."""
        visible = self.visible_names()
        seen: dict[str, UdfName] = {}
        for n in self.names:
            if n.is_parent or not n.name or n.is_dir:
                continue
            if n.name in visible and not n.deleted_flag:
                continue
            seen.setdefault(n.name, n)
        return list(seen.values())


def scan(fh: BinaryIO, start: int = 0, end: Optional[int] = None) -> UdfScan:
    total = stream_size(fh)
    end = min(end or total, total)
    result = UdfScan()
    by_location: dict[int, UdfFile] = {}
    chunk_sectors = 4096
    pos = start - (start % SECTOR)
    while pos < end:
        fh.seek(pos)
        data = fh.read(min(chunk_sectors * SECTOR, end - pos))
        if not data:
            break
        for rel in range(0, len(data), SECTOR):
            block = data[rel: rel + SECTOR]
            ident = _tag_ok(block[:16])
            if ident is None:
                continue
            sector = (pos + rel) // SECTOR
            if ident == TAG_PD and not result.partition_start:
                result.partition_start = struct.unpack_from("<I", block, 188)[0]
            elif ident == TAG_FID:
                result.names.extend(parse_fids(block, sector))
            elif ident in (TAG_FE, TAG_EFE):
                parsed = parse_file_entry(block, sector, ident)
                if parsed:
                    f, inline = parsed
                    result.files.append(f)
                    by_location.setdefault(f.tag_location, f)
                    result.names.extend(inline)
        pos += len(data)
    for n in result.names:
        f = by_location.get(n.icb_block)
        if f is not None and not n.is_parent:
            f.names.append(n)
    return result


def read_file(fh: BinaryIO, result: UdfScan, f: UdfFile, base: int = 0, limit: int = 256 * 1024 * 1024) -> bytes:
    """Read a file's content through its allocation extents (physical partition only)."""
    out = bytearray()
    for block, length in f.extents:
        fh.seek(base + (result.partition_start + block) * SECTOR)
        out += fh.read(min(length, limit - len(out)))
        if len(out) >= limit:
            break
    return bytes(out[: f.size]) if f.size else bytes(out)


def entry_for(result: UdfScan, name: str) -> Optional[UdfFile]:
    for f in result.files:
        if f.file_type == 5 and any(n.name == name for n in f.names):
            return f
    return None
