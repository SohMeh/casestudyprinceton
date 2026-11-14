"""FAT32 recovery that still works after a quick format.

A quick format rewrites the boot sector, zeroes the FAT and resets the root
directory, but it does not touch the data area. Old subdirectory clusters are
still there, and each one starts with the "." and ".." entries. We scan every
cluster for that pattern, parse the directory entries we find, and read each
file's content from its start cluster.

Because the FAT is gone we assume files were stored contiguously. That holds
for files copied onto a fresh stick, and every recovered file is validated
afterwards by its content.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import BinaryIO, Iterator, Optional

ATTR_READ_ONLY = 0x01
ATTR_HIDDEN = 0x02
ATTR_SYSTEM = 0x04
ATTR_VOLUME_ID = 0x08
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_LFN = 0x0F

DOT = b".          "
DOTDOT = b"..         "


@dataclass
class Bpb:
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    total_sectors: int
    fat_size: int
    root_cluster: int
    label: str

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def fat_offset(self) -> int:
        return self.reserved_sectors * self.bytes_per_sector

    @property
    def data_offset(self) -> int:
        return (self.reserved_sectors + self.num_fats * self.fat_size) * self.bytes_per_sector

    @property
    def cluster_count(self) -> int:
        data_sectors = self.total_sectors - (self.reserved_sectors + self.num_fats * self.fat_size)
        return max(0, data_sectors // self.sectors_per_cluster)

    def cluster_offset(self, cluster: int) -> int:
        return self.data_offset + (cluster - 2) * self.cluster_size


@dataclass
class DirEntry:
    name: str
    short_name: str
    attr: int
    deleted: bool
    start_cluster: int
    size: int
    created: Optional[datetime]
    modified: Optional[datetime]
    accessed: Optional[datetime]
    entry_offset: int                 # byte offset of the 32-byte entry in the volume
    dir_cluster: int                  # cluster of the directory holding the entry
    path: str = ""

    @property
    def is_dir(self) -> bool:
        return bool(self.attr & ATTR_DIRECTORY)

    @property
    def is_volume_label(self) -> bool:
        return bool(self.attr & ATTR_VOLUME_ID) and not self.is_dir


@dataclass
class OrphanDir:
    cluster: int
    parent_cluster: int
    created: Optional[datetime]
    entries: list[DirEntry] = field(default_factory=list)
    name: str = ""
    path: str = ""


def parse_bpb(boot: bytes) -> Bpb:
    if len(boot) < 512 or boot[510:512] != b"\x55\xaa":
        raise ValueError("not a boot sector")
    bps, spc, reserved, nfats = struct.unpack_from("<HBHB", boot, 11)
    total16 = struct.unpack_from("<H", boot, 19)[0]
    total32 = struct.unpack_from("<I", boot, 32)[0]
    fat_size32 = struct.unpack_from("<I", boot, 36)[0]
    root_cluster = struct.unpack_from("<I", boot, 44)[0]
    label = boot[71:82].decode("ascii", "replace").strip()
    if bps not in (512, 1024, 2048, 4096) or spc == 0 or fat_size32 == 0:
        raise ValueError("not a FAT32 volume")
    return Bpb(bps, spc, reserved, nfats, total16 or total32, fat_size32, root_cluster, label)


def _fat_datetime(date: int, time: int, tenths: int = 0) -> Optional[datetime]:
    """FAT stores local wall-clock time with no zone. Returned naive on purpose."""
    if date == 0:
        return None
    year = 1980 + (date >> 9)
    month = (date >> 5) & 0x0F
    day = date & 0x1F
    hour = time >> 11
    minute = (time >> 5) & 0x3F
    second = (time & 0x1F) * 2 + (tenths // 100)
    try:
        return datetime(year, month, day, hour, minute, min(second, 59))
    except ValueError:
        return None


def _short_name(raw: bytes, ntres: int, deleted: bool) -> str:
    base = raw[:8]
    ext = raw[8:11]
    if deleted:
        base = b"_" + base[1:]          # first character was overwritten by 0xE5
    b = base.decode("cp437", "replace").rstrip()
    e = ext.decode("cp437", "replace").rstrip()
    if ntres & 0x08:
        b = b.lower()
    if ntres & 0x10:
        e = e.lower()
    return f"{b}.{e}" if e else b


def _lfn_piece(entry: bytes) -> str:
    raw = entry[1:11] + entry[14:26] + entry[28:32]
    text = raw.decode("utf-16-le", "replace")
    end = text.find("\x00")
    if end >= 0:
        text = text[:end]
    return text.replace("￿", "")


def _plausible_short_entry(e: bytes) -> bool:
    attr = e[11]
    if attr == ATTR_LFN:
        return True
    if attr & 0xC0:                       # reserved bits must be clear
        return False
    name = e[:11]
    if name[0] in (0x00,):
        return False
    # Short names are upper-case printable characters, padded with spaces.
    for i, ch in enumerate(name):
        if i == 0 and ch == 0xE5:
            continue
        if ch < 0x20 or ch in b'"*+,/:;<=>?[\\]|':
            return False
    return True


def parse_directory(data: bytes, base_offset: int, dir_cluster: int) -> list[DirEntry]:
    """Parse raw directory bytes into entries, rebuilding long file names."""
    entries: list[DirEntry] = []
    lfn_parts: list[str] = []
    for i in range(0, len(data) - 31, 32):
        e = data[i: i + 32]
        first = e[0]
        if first == 0x00:
            break                         # end of directory
        attr = e[11]
        if attr == ATTR_LFN:
            lfn_parts.append(_lfn_piece(e))
            continue
        if not _plausible_short_entry(e):
            lfn_parts = []
            continue
        deleted = first == 0xE5
        ntres = e[12]
        tenths = e[13]
        ctime, cdate, adate, hi, wtime, wdate, lo, size = struct.unpack_from("<HHHHHHHI", e, 14)
        short = _short_name(e[:11], ntres, deleted)
        long_name = "".join(reversed(lfn_parts)) if lfn_parts else ""
        lfn_parts = []
        if e[:11] in (DOT, DOTDOT):
            name = short.strip() or "."
            name = "." if e[:11] == DOT else ".."
        else:
            name = long_name or short
        entries.append(
            DirEntry(
                name=name,
                short_name=short,
                attr=attr,
                deleted=deleted,
                start_cluster=(hi << 16) | lo,
                size=size,
                created=_fat_datetime(cdate, ctime, tenths),
                modified=_fat_datetime(wdate, wtime),
                accessed=_fat_datetime(adate, 0),
                entry_offset=base_offset + i,
                dir_cluster=dir_cluster,
            )
        )
    return entries


class Fat32Volume:
    """Read-only FAT32 volume with orphan-directory recovery."""

    def __init__(self, fh: BinaryIO):
        self.fh = fh
        fh.seek(0)
        self.bpb = parse_bpb(fh.read(512))

    # -- low level -----------------------------------------------------
    def read_at(self, offset: int, size: int) -> bytes:
        self.fh.seek(offset)
        return self.fh.read(size)

    def read_cluster(self, cluster: int, count: int = 1) -> bytes:
        return self.read_at(self.bpb.cluster_offset(cluster), self.bpb.cluster_size * count)

    def valid_cluster(self, cluster: int) -> bool:
        return 2 <= cluster < self.bpb.cluster_count + 2

    # -- current (post-format) state ----------------------------------
    def fat_allocated_clusters(self) -> int:
        """How many clusters the current FAT says are in use."""
        size = min(self.bpb.fat_size * self.bpb.bytes_per_sector, (self.bpb.cluster_count + 2) * 4)
        data = self.read_at(self.bpb.fat_offset, size)
        used = 0
        for (value,) in struct.iter_unpack("<I", data[: len(data) - len(data) % 4]):
            if value & 0x0FFFFFFF:
                used += 1
        return max(0, used - 2)           # first two entries are reserved

    def root_entries(self) -> list[DirEntry]:
        if not self.valid_cluster(self.bpb.root_cluster):
            return []
        data = self.read_cluster(self.bpb.root_cluster)
        ents = parse_directory(data, self.bpb.cluster_offset(self.bpb.root_cluster), self.bpb.root_cluster)
        for e in ents:
            e.path = "\\" + e.name
        return ents

    # -- live tree (what the file system shows today) -------------------
    def fat_table(self) -> list[int]:
        if not hasattr(self, "_fat"):
            size = min(self.bpb.fat_size * self.bpb.bytes_per_sector, (self.bpb.cluster_count + 2) * 4)
            data = self.read_at(self.bpb.fat_offset, size)
            self._fat = [v & 0x0FFFFFFF for (v,) in struct.iter_unpack("<I", data[: len(data) - len(data) % 4])]
        return self._fat

    def chain(self, start: int, limit: int = 1 << 20) -> list[int]:
        fat = self.fat_table()
        out: list[int] = []
        c = start
        while self.valid_cluster(c) and c < len(fat) and len(out) < limit:
            out.append(c)
            nxt = fat[c]
            if nxt >= 0x0FFFFFF8 or nxt < 2:
                break
            c = nxt
        return out

    def read_chain(self, start: int, size: Optional[int] = None) -> bytes:
        data = b"".join(self.read_cluster(c) for c in self.chain(start))
        return data if size is None else data[:size]

    def volume_label_entry(self) -> Optional[DirEntry]:
        for e in self.root_entries():
            if e.is_volume_label and not e.deleted:
                return e
        return None

    def walk_live(self, cluster: Optional[int] = None, path: str = "", depth: int = 0) -> Iterator[DirEntry]:
        """Files and folders reachable from the root directory through the FAT."""
        if depth > 32:
            return
        cluster = self.bpb.root_cluster if cluster is None else cluster
        if not self.valid_cluster(cluster):
            return
        data = self.read_chain(cluster)
        for e in parse_directory(data, self.bpb.cluster_offset(cluster), cluster):
            if e.name in (".", "..") or e.is_volume_label or e.deleted:
                continue
            e.path = f"{path}\\{e.name}"
            yield e
            if e.is_dir and self.valid_cluster(e.start_cluster):
                yield from self.walk_live(e.start_cluster, e.path, depth + 1)

    def read_live(self, entry: DirEntry) -> bytes:
        return self.read_chain(entry.start_cluster, entry.size) if entry.size else b""

    # -- recovery ------------------------------------------------------
    def scan_orphan_directories(self) -> list[OrphanDir]:
        """Find every cluster that starts with "." and ".." directory entries."""
        bpb = self.bpb
        found: list[OrphanDir] = []
        batch = max(1, (8 * 1024 * 1024) // bpb.cluster_size)
        cluster = 2
        last = bpb.cluster_count + 2
        while cluster < last:
            n = min(batch, last - cluster)
            data = self.read_cluster(cluster, n)
            for i in range(n):
                off = i * bpb.cluster_size
                head = data[off: off + 64]
                if len(head) < 64:
                    break
                if head[0:11] == DOT and head[32:43] == DOTDOT and head[11] & ATTR_DIRECTORY and head[43] & ATTR_DIRECTORY:
                    c = cluster + i
                    found.append(self._parse_orphan(c))
            cluster += n
        self._resolve_paths(found)
        return found

    def _parse_orphan(self, cluster: int) -> OrphanDir:
        bpb = self.bpb
        chunks = []
        c = cluster
        # Without a FAT we follow the directory through adjacent clusters
        # until an end-of-directory marker shows up.
        for _ in range(64):
            if not self.valid_cluster(c):
                break
            block = self.read_cluster(c)
            chunks.append(block)
            ended = any(block[i] == 0x00 for i in range(0, len(block), 32))
            if ended:
                break
            c += 1
        data = b"".join(chunks)
        entries = parse_directory(data, bpb.cluster_offset(cluster), cluster)
        dot = entries[0] if entries else None
        dotdot = entries[1] if len(entries) > 1 else None
        od = OrphanDir(
            cluster=cluster,
            parent_cluster=dotdot.start_cluster if dotdot else 0,
            created=dot.created if dot else None,
        )
        od.entries = [e for e in entries if e.name not in (".", "..")]
        return od

    def _resolve_paths(self, dirs: list[OrphanDir]) -> None:
        by_cluster = {d.cluster: d for d in dirs}
        # A directory's own name lives in its parent's listing.
        for d in dirs:
            for e in d.entries:
                if e.is_dir and e.start_cluster in by_cluster:
                    by_cluster[e.start_cluster].name = e.name

        def path_of(d: OrphanDir, depth: int = 0) -> str:
            if d.path:
                return d.path
            name = d.name or "(folder name lost)"
            parent = by_cluster.get(d.parent_cluster)
            if parent is None or depth > 32:
                d.path = "\\" + name
            else:
                d.path = path_of(parent, depth + 1) + "\\" + name
            return d.path

        for d in dirs:
            path_of(d)
            for e in d.entries:
                e.path = d.path + "\\" + e.name

    def read_file(self, entry: DirEntry) -> bytes:
        """Read a file's bytes assuming contiguous storage from its start cluster."""
        if entry.size == 0 or not self.valid_cluster(entry.start_cluster):
            return b""
        off = self.bpb.cluster_offset(entry.start_cluster)
        return self.read_at(off, entry.size)

    def iter_recoverable(self, dirs: list[OrphanDir]) -> Iterator[DirEntry]:
        for d in dirs:
            for e in d.entries:
                if not e.is_dir and not e.is_volume_label and e.size > 0:
                    yield e
