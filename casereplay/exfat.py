"""Minimal read-only exFAT reader that also reports deleted entries.

exFAT marks a deleted file by clearing the top bit of each entry type in its
directory entry set (0x85 becomes 0x05 and so on). The name, size, start
cluster and timestamps stay in place until something overwrites them.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import BinaryIO, Iterator, Optional

EOC = 0xFFFFFFFF


@dataclass
class ExEntry:
    name: str
    path: str
    is_dir: bool
    deleted: bool
    size: int
    first_cluster: int
    contiguous: bool
    created: Optional[datetime]       # timezone-aware when the entry stores an offset
    modified: Optional[datetime]
    accessed: Optional[datetime]
    entry_offset: int


def _ts(value: int, tenms: int, tz: int) -> Optional[datetime]:
    if value == 0:
        return None
    year = 1980 + (value >> 25)
    month = (value >> 21) & 0x0F
    day = (value >> 16) & 0x1F
    hour = (value >> 11) & 0x1F
    minute = (value >> 5) & 0x3F
    second = (value & 0x1F) * 2 + tenms // 100
    try:
        dt = datetime(year, month, day, hour, minute, min(second, 59))
    except ValueError:
        return None
    if tz & 0x80:                        # offset is valid: 15-minute steps, 7-bit signed
        q = tz & 0x7F
        if q >= 64:
            q -= 128
        dt = dt.replace(tzinfo=timezone(timedelta(minutes=15 * q)))
    return dt


class ExFatVolume:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        fh.seek(0)
        vbr = fh.read(512)
        if vbr[3:11] != b"EXFAT   ":
            raise ValueError("not an exFAT volume")
        (self.fat_offset, self.fat_length, self.heap_offset, self.cluster_count,
         self.root_cluster) = struct.unpack_from("<IIIII", vbr, 80)
        self.sector_size = 1 << vbr[108]
        self.cluster_size = self.sector_size << vbr[109]
        self.label = ""

    def cluster_offset(self, cluster: int) -> int:
        return self.heap_offset * self.sector_size + (cluster - 2) * self.cluster_size

    def _read(self, offset: int, size: int) -> bytes:
        self.fh.seek(offset)
        return self.fh.read(size)

    def _chain(self, first: int, limit: int = 1 << 20) -> list[int]:
        chain = []
        c = first
        while 2 <= c < self.cluster_count + 2 and len(chain) < limit:
            chain.append(c)
            raw = self._read(self.fat_offset * self.sector_size + c * 4, 4)
            if len(raw) < 4:
                break
            c = struct.unpack("<I", raw)[0]
            if c == EOC or c == 0:
                break
        return chain

    def read_data(self, first_cluster: int, size: int, contiguous: bool) -> bytes:
        if size == 0 or first_cluster < 2:
            return b""
        if contiguous:
            return self._read(self.cluster_offset(first_cluster), size)
        out = bytearray()
        for c in self._chain(first_cluster):
            out += self._read(self.cluster_offset(c), self.cluster_size)
            if len(out) >= size:
                break
        return bytes(out[:size])

    def _dir_bytes(self, first_cluster: int, contiguous: bool, size: int) -> tuple[bytes, list[int]]:
        if contiguous and size:
            n = -(-size // self.cluster_size)
            clusters = list(range(first_cluster, first_cluster + n))
        else:
            clusters = self._chain(first_cluster)
        data = b"".join(self._read(self.cluster_offset(c), self.cluster_size) for c in clusters)
        return data, clusters

    def walk(self, first_cluster: Optional[int] = None, path: str = "", contiguous: bool = False,
             size: int = 0, depth: int = 0) -> Iterator[ExEntry]:
        """Yield every file and folder, including deleted ones."""
        if depth > 32:
            return
        cluster = first_cluster if first_cluster is not None else self.root_cluster
        data, clusters = self._dir_bytes(cluster, contiguous, size)
        i = 0
        n = len(data)
        while i + 32 <= n:
            etype = data[i]
            if etype == 0x00:
                break
            if etype == 0x83:
                length = data[i + 1]
                self.label = data[i + 2: i + 2 + length * 2].decode("utf-16-le", "replace")
            if etype & 0x7F != 0x05:
                i += 32
                continue
            deleted = not (etype & 0x80)
            secondary = data[i + 1]
            attrs = struct.unpack_from("<H", data, i + 4)[0]
            c_ts, m_ts, a_ts = struct.unpack_from("<III", data, i + 8)
            c10, m10, ctz, mtz, atz = data[i + 20], data[i + 21], data[i + 22], data[i + 23], data[i + 24]
            name = ""
            first = 0
            dlen = 0
            contig = False
            name_len = 0
            for k in range(1, secondary + 1):
                j = i + 32 * k
                if j + 32 > n:
                    break
                st = data[j] & 0x7F
                if st == 0x40:
                    contig = bool(data[j + 1] & 0x02)
                    name_len = data[j + 3]
                    first = struct.unpack_from("<I", data, j + 20)[0]
                    dlen = struct.unpack_from("<Q", data, j + 24)[0]
                elif st == 0x41:
                    name += data[j + 2: j + 32].decode("utf-16-le", "replace")
            name = name[:name_len] if name_len else name.rstrip("\x00")
            cl_index = i // self.cluster_size
            entry_off = self.cluster_offset(clusters[cl_index]) + (i % self.cluster_size) if cl_index < len(clusters) else 0
            entry = ExEntry(
                name=name, path=f"{path}\\{name}", is_dir=bool(attrs & 0x10), deleted=deleted,
                size=dlen, first_cluster=first, contiguous=contig,
                created=_ts(c_ts, c10, ctz), modified=_ts(m_ts, m10, mtz), accessed=_ts(a_ts, 0, atz),
                entry_offset=entry_off,
            )
            yield entry
            if entry.is_dir and first >= 2 and not deleted:
                yield from self.walk(first, entry.path, contig, dlen, depth + 1)
            i += 32 * (secondary + 1)
