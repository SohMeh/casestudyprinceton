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
TAG_LVD = 6
TAG_FSD = 256
VAT_FILE_TYPE = 248
UNMAPPED = 0xFFFFFFFF


@dataclass
class UdfName:
    name: str
    sector: int                 # sector of the directory block holding this entry
    deleted_flag: bool
    is_dir: bool
    is_parent: bool
    icb_block: int              # logical block of the file's File Entry
    icb_part: int = 0           # partition reference: 0 physical, otherwise the virtual partition


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
    if ident not in (TAG_FID, TAG_FE, TAG_EFE, TAG_PD, TAG_LVD, TAG_FSD):
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


def _dstring_fixed(raw: bytes) -> str:
    """A fixed-width dstring: the last byte holds how many bytes are in use."""
    if not raw or raw[-1] < 2:
        return ""
    return _dstring(raw[: raw[-1]]).rstrip("\x00 ")


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
            icb_part=struct.unpack_from("<H", data, pos + 28)[0],
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
    label: str = ""
    root_icb: Optional[tuple[int, int]] = None          # (block, partition reference) of the root directory
    vat_sectors: list[int] = field(default_factory=list)

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
            if ident == TAG_PD:
                if not result.partition_start:
                    result.partition_start = struct.unpack_from("<I", block, 188)[0]
            elif ident == TAG_LVD:
                result.label = result.label or _dstring_fixed(block[84:212])
            elif ident == TAG_FSD:
                if result.root_icb is None:
                    result.root_icb = (struct.unpack_from("<I", block, 404)[0], struct.unpack_from("<H", block, 408)[0])
            elif ident == TAG_FE and block[27] == VAT_FILE_TYPE:
                result.vat_sectors.append(sector)
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


# -- disc history on write-once media ----------------------------------------
#
# A disc written with a "live" file system keeps a Virtual Allocation Table
# (VAT). Every time the disc is ejected a new VAT is written at the end, and
# the old ones stay. Each VAT is a complete snapshot of which directory and
# file entries were current at that moment, with a timestamp. Reading all of
# them in order replays what was put on the disc, renamed and removed, and when.

@dataclass
class UdfNode:
    vblock: int                     # virtual address: stays the same when the entry is rewritten
    name: str
    path: str
    is_dir: bool
    fe_sector: Optional[int]
    size: int = 0
    modified: Optional[datetime] = None
    created: Optional[datetime] = None
    extents: list[tuple[int, int]] = field(default_factory=list)
    inline: Optional[bytes] = None

    def data_sector(self, partition_start: int) -> Optional[int]:
        return partition_start + self.extents[0][0] if self.extents else None


@dataclass
class UdfSnapshot:
    index: int
    vat_sector: Optional[int]
    time: Optional[datetime]
    nodes: dict[int, UdfNode] = field(default_factory=dict)

    def files(self) -> list[UdfNode]:
        return [n for n in self.nodes.values() if not n.is_dir]


@dataclass
class UdfChange:
    kind: str                       # added | renamed | removed
    time: Optional[datetime]
    snapshot: int
    node: UdfNode
    old_name: str = ""


def _fe_raw(block: bytes) -> Optional[dict]:
    ident = _tag_ok(block[:16])
    if ident not in (TAG_FE, TAG_EFE):
        return None
    try:
        flags = struct.unpack_from("<H", block, 34)[0]
        size = struct.unpack_from("<Q", block, 56)[0]
        if ident == TAG_FE:
            modified, created = _timestamp(block[84:96]), None
            l_ea, l_ad = struct.unpack_from("<II", block, 168)
            off = 176 + l_ea
        else:
            modified, created = _timestamp(block[92:104]), _timestamp(block[104:116])
            l_ea, l_ad = struct.unpack_from("<II", block, 208)
            off = 216 + l_ea
    except struct.error:
        return None
    ads = block[off: off + l_ad]
    ad_type = flags & 0x07
    extents: list[tuple[int, int]] = []
    step = 8 if ad_type == 0 else 16 if ad_type == 1 else 0
    if step:
        for i in range(0, len(ads) - step + 1, step):
            length, pos = struct.unpack_from("<II", ads, i)
            if length & 0x3FFFFFFF:
                extents.append((pos, length & 0x3FFFFFFF))
    return {"type": block[27], "ad_type": ad_type, "size": size, "modified": modified, "created": created,
            "extents": extents, "inline": bytes(ads[:size]) if ad_type == 3 else None}


def _sector(fh: BinaryIO, base: int, sector: int) -> bytes:
    fh.seek(base + sector * SECTOR)
    return fh.read(SECTOR)


def _content(fh: BinaryIO, base: int, pstart: int, raw: dict, limit: int = 256 * 1024 * 1024) -> bytes:
    if raw["inline"] is not None:
        return raw["inline"]
    out = bytearray()
    for block, length in raw["extents"]:
        fh.seek(base + (pstart + block) * SECTOR)
        out += fh.read(min(length, limit - len(out)))
        if len(out) >= limit:
            break
    return bytes(out[: raw["size"]]) if raw["size"] else bytes(out)


def node_bytes(fh: BinaryIO, base: int, result: UdfScan, node: UdfNode) -> bytes:
    return _content(fh, base, result.partition_start,
                    {"inline": node.inline, "extents": node.extents, "size": node.size})


def read_vat(fh: BinaryIO, base: int, pstart: int, sector: int) -> Optional[tuple[Optional[datetime], list[int]]]:
    raw = _fe_raw(_sector(fh, base, sector))
    if not raw or raw["type"] != VAT_FILE_TYPE:
        return None
    data = _content(fh, base, pstart, raw)
    if len(data) < 152:
        return None
    header = struct.unpack_from("<H", data, 0)[0]
    if header < 152 or header > len(data):
        return None
    body = data[header:]
    table = [v for (v,) in struct.iter_unpack("<I", body[: len(body) - len(body) % 4])]
    return raw["modified"], table


def _tree(fh: BinaryIO, base: int, pstart: int, vat: Optional[list[int]], root: tuple[int, int]) -> dict[int, UdfNode]:
    nodes: dict[int, UdfNode] = {}

    def resolve(block: int, part: int) -> Optional[int]:
        if vat is None or part == 0:
            return pstart + block
        if block < len(vat) and vat[block] != UNMAPPED:
            return pstart + vat[block]
        return None

    def walk(block: int, part: int, path: str, depth: int) -> None:
        sector = resolve(block, part)
        if sector is None or depth > 24:
            return
        raw = _fe_raw(_sector(fh, base, sector))
        if not raw or raw["type"] != 4:
            return
        for fid in parse_fids(_content(fh, base, pstart, raw, 8 * 1024 * 1024), sector):
            if fid.is_parent or fid.deleted_flag or not fid.name:
                continue
            child_sector = resolve(fid.icb_block, fid.icb_part)
            craw = _fe_raw(_sector(fh, base, child_sector)) if child_sector is not None else None
            key = fid.icb_block if fid.icb_part else -(fid.icb_block + 1)
            if key in nodes:
                continue
            nodes[key] = UdfNode(
                vblock=key, name=fid.name, path=f"{path}\\{fid.name}", is_dir=fid.is_dir, fe_sector=child_sector,
                size=craw["size"] if craw else 0, modified=craw["modified"] if craw else None,
                created=craw["created"] if craw else None, extents=craw["extents"] if craw else [],
                inline=craw["inline"] if craw and not fid.is_dir else None)
            if fid.is_dir:
                walk(fid.icb_block, fid.icb_part, nodes[key].path, depth + 1)

    walk(root[0], root[1], "", 0)
    return nodes


def snapshots(fh: BinaryIO, result: UdfScan, base: int = 0) -> list[UdfSnapshot]:
    """Every recorded state of the disc, oldest first. One state for a disc without a VAT."""
    if result.root_icb is None:
        return []
    out: list[UdfSnapshot] = []
    if not result.vat_sectors:
        nodes = _tree(fh, base, result.partition_start, None, result.root_icb)
        return [UdfSnapshot(0, None, None, nodes)] if nodes else []
    for sector in sorted(result.vat_sectors):
        got = read_vat(fh, base, result.partition_start, sector)
        if not got:
            continue
        when, table = got
        out.append(UdfSnapshot(len(out), sector, when, _tree(fh, base, result.partition_start, table, result.root_icb)))
    return out


def history(snaps: list[UdfSnapshot]) -> list[UdfChange]:
    """What changed between consecutive states: entries added, renamed and removed."""
    changes: list[UdfChange] = []
    for prev, cur in zip([UdfSnapshot(-1, None, None)] + snaps[:-1], snaps):
        for key, node in cur.nodes.items():
            before = prev.nodes.get(key)
            if before is None:
                changes.append(UdfChange("added", cur.time, cur.index, node))
            elif before.name != node.name:
                changes.append(UdfChange("renamed", cur.time, cur.index, node, old_name=before.name))
        for key, node in prev.nodes.items():
            if key not in cur.nodes:
                changes.append(UdfChange("removed", cur.time, cur.index, node))
    return changes
