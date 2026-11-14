"""Generate a small synthetic practice case.

Everything here is invented: the company (Halcyon Robotics), the project
(Kestrel) and the people. It exists so the whole pipeline can be run, tested
and demoed in seconds without downloading real evidence. The structures are
real though: a quick-formatted FAT32 stick, an exFAT stick with a deleted
entry, a write-once disc with an old and a new directory, and a triage export
of computer artifacts.
"""
from __future__ import annotations

import io
import json
import struct
import zlib
from datetime import datetime
from pathlib import Path

from .ledger import Case, CaseStore, ImageRef

BPS = 512
SPC = 1
RESERVED = 32
NFATS = 2
TOTAL_SECTORS = 40000
FAT_SIZE = 320


# -- documents ---------------------------------------------------------------

def make_docx(text: str) -> bytes:
    from docx import Document

    doc = Document()
    doc.core_properties.title = text[:200]
    doc.core_properties.author = "r.vance"
    doc.add_paragraph(text)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def make_pptx(text: str) -> bytes:
    from pptx import Presentation

    prs = Presentation()
    slide = prs.slides.add_slide(prs.slide_layouts[0])
    slide.shapes.title.text = text
    buf = io.BytesIO()
    prs.save(buf)
    return buf.getvalue()


def make_xlsx(text: str) -> bytes:
    from openpyxl import Workbook

    wb = Workbook()
    wb.active["A1"] = text
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def make_ole2(stream_name: str = "WordDocument", data_sectors: int = 6, fill: int = 65) -> bytes:
    """A minimal OLE2 container: header, one FAT sector, some data sectors."""
    hdr = bytearray(512)
    hdr[0:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    struct.pack_into("<H", hdr, 24, 0x3E)
    struct.pack_into("<H", hdr, 26, 3)
    struct.pack_into("<H", hdr, 28, 0xFFFE)
    struct.pack_into("<H", hdr, 30, 9)
    struct.pack_into("<H", hdr, 32, 6)
    struct.pack_into("<I", hdr, 44, 1)
    struct.pack_into("<I", hdr, 48, 1)
    struct.pack_into("<I", hdr, 60, 0xFFFFFFFE)
    struct.pack_into("<I", hdr, 68, 0xFFFFFFFE)
    difat = [0] + [0xFFFFFFFF] * 108
    struct.pack_into("<109I", hdr, 76, *difat)
    fat = [0xFFFFFFFF] * 128
    fat[0] = 0xFFFFFFFD
    for i in range(1, 1 + data_sectors):
        fat[i] = 0xFFFFFFFE
    body = bytearray(struct.pack("<128I", *fat))
    directory = bytearray(512)
    name = stream_name.encode("utf-16-le")
    directory[0: len(name)] = name
    body += directory
    for i in range(data_sectors - 1):
        body += bytes([(fill + i) % 250 + 1]) * 512
    return bytes(hdr + body)


def make_png(seed: int = 0, size: int = 96) -> bytes:
    """A real, viewable PNG (a colour gradient)."""
    rows = bytearray()
    for y in range(size):
        rows.append(0)
        for x in range(size):
            rows += bytes(((x * 2 + seed * 40) % 256, (y * 2 + seed * 90) % 256, (x + y + seed * 17) % 256))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(bytes(rows))) + chunk(b"IEND", b"")


# -- FAT32 -------------------------------------------------------------------

def _fat_dt(dt: datetime) -> tuple[int, int]:
    date = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    time = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return date, time


def _short(name: str, index: int) -> bytes:
    base, _, ext = name.rpartition(".")
    if not base:
        base, ext = name, ""
    b = "".join(ch for ch in base.upper() if ch.isalnum())[:6] or "FILE"
    e = "".join(ch for ch in ext.upper() if ch.isalnum())[:3]
    return f"{b}~{index % 10}".ljust(8).encode("ascii") + e.ljust(3).encode("ascii")


def _checksum(short: bytes) -> int:
    s = 0
    for ch in short:
        s = (((s & 1) << 7) + (s >> 1) + ch) & 0xFF
    return s


def dir_entries(name: str, attr: int, cluster: int, size: int, dt: datetime, index: int = 1,
                deleted: bool = False) -> bytes:
    """LFN entries followed by the 8.3 entry, as Windows writes them."""
    short = _short(name, index)
    csum = _checksum(short)
    units = name.encode("utf-16-le") + b"\x00\x00"
    while len(units) % 26:
        units += b"\xff\xff"
    pieces = [units[i: i + 26] for i in range(0, len(units), 26)]
    out = bytearray()
    for seq in range(len(pieces), 0, -1):
        p = pieces[seq - 1]
        e = bytearray(32)
        e[0] = seq | (0x40 if seq == len(pieces) else 0)
        e[1:11] = p[0:10]
        e[11] = 0x0F
        e[13] = csum
        e[14:26] = p[10:22]
        e[28:32] = p[22:26]
        if deleted:
            e[0] = 0xE5
        out += e
    date, time = _fat_dt(dt)
    e = bytearray(32)
    e[0:11] = short
    e[11] = attr
    struct.pack_into("<HHHHHHHI", e, 14, time, date, date, cluster >> 16, time, date, cluster & 0xFFFF, size)
    if deleted:
        e[0] = 0xE5
    out += e
    return bytes(out)


def dot_entries(cluster: int, parent: int, dt: datetime) -> bytes:
    date, time = _fat_dt(dt)
    out = bytearray()
    for name, c in ((b".          ", cluster), (b"..         ", parent)):
        e = bytearray(32)
        e[0:11] = name
        e[11] = 0x10
        struct.pack_into("<HHHHHHHI", e, 14, time, date, date, c >> 16, time, date, c & 0xFFFF, 0)
        out += e
    return bytes(out)


def build_formatted_stick(path: Path, files: dict | None = None, label: bytes = b"IAMAN $_@  ",
                          copied: datetime = datetime(2015, 3, 24, 9, 58, 40),
                          formatted: datetime = datetime(2015, 3, 24, 17, 2, 10),
                          stray: bytes | None = None, top_name: str = "") -> dict:
    """Write a quick-formatted FAT32 image and return what should be recoverable."""
    img = bytearray(TOTAL_SECTORS * BPS)
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x58\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<HBHB", boot, 11, BPS, SPC, RESERVED, NFATS)
    struct.pack_into("<I", boot, 32, TOTAL_SECTORS)
    struct.pack_into("<I", boot, 36, FAT_SIZE)
    struct.pack_into("<I", boot, 44, 2)
    boot[71:82] = label
    boot[82:90] = b"FAT32   "
    boot[510:512] = b"\x55\xaa"
    img[0:512] = boot
    data_off = (RESERVED + NFATS * FAT_SIZE) * BPS

    def coff(c: int) -> int:
        return data_off + (c - 2) * BPS * SPC

    if files is None:
        files = {
            "design": [
                ("winter_storm.amr", make_ole2("PowerPoint Document", 9), "PPT"),
                ("winter_whether_advisory.zip", make_pptx("[secret_project] detailed design"), "PPTX"),
            ],
            "proposal": [
                ("landscape.png", make_docx("[secret_project] proposal"), "DOCX"),
                ("a_gift_from_you.gif", make_docx("[secret_project] detailed proposal"), "DOCX"),
            ],
            "pricing decision": [
                ("new_years_day.jpg", make_xlsx("(secret_project) market analysis"), "XLSX"),
            ],
        }
    if stray is None:
        stray = make_docx("[secret_project] progress")

    next_cluster = 3
    top = next_cluster
    next_cluster += 1
    top_dir = bytearray(dot_entries(top, 0, copied))
    expected = []
    idx = 1
    for dname, flist in files.items():
        dcluster = next_cluster
        next_cluster += 1
        top_dir += dir_entries(dname, 0x10, dcluster, 0, copied, idx)
        idx += 1
        d = bytearray(dot_entries(dcluster, top, copied))
        for fname, content, ftype in flist:
            nclus = -(-len(content) // (BPS * SPC))
            start = next_cluster
            next_cluster += nclus
            img[coff(start): coff(start) + len(content)] = content
            d += dir_entries(fname, 0x20, start, len(content), copied, idx)
            idx += 1
            expected.append({"name": fname, "dir": dname, "type": ftype, "size": len(content), "bytes": content})
        img[coff(dcluster): coff(dcluster) + len(d)] = d
    img[coff(top): coff(top) + len(top_dir)] = top_dir

    # A file with no directory entry at all, to exercise carving.
    stray_cluster = next_cluster + 50
    img[coff(stray_cluster): coff(stray_cluster) + len(stray)] = stray

    # Quick format: FATs zeroed apart from the reserved entries, root reset to a label.
    fat0 = RESERVED * BPS
    for n in range(NFATS):
        base = fat0 + n * FAT_SIZE * BPS
        struct.pack_into("<III", img, base, 0x0FFFFFF8, 0x0FFFFFFF, 0x0FFFFFFF)
    date, time = _fat_dt(formatted)
    lab = bytearray(32)
    lab[0:11] = label
    lab[11] = 0x08
    struct.pack_into("<HH", lab, 22, time, date)
    img[coff(2): coff(2) + 32] = lab

    path.write_bytes(bytes(img))
    return {"files": expected, "stray": stray, "copied": copied, "formatted": formatted}


def build_disc(path: Path) -> list[dict]:
    """A raw blob with files at 2048-byte sector boundaries, like an optical image."""
    items = [
        ("PPT", make_ole2("PowerPoint Document", 12)),
        ("DOCX", make_docx("[secret_project] technical review #1")),
        ("XLSX", make_xlsx("(secret_project) price analysis #1")),
        ("XLS", make_ole2("Workbook", 5)),
        ("PPTX", make_pptx("[secret_project] final meeting")),
    ]
    blob = bytearray(2048 * 40)
    out = []
    for ftype, content in items:
        off = len(blob)
        blob += content
        blob += b"\x00" * (-len(blob) % 2048)
        blob += b"\x11" * 2048
        out.append({"type": ftype, "offset": off, "size": len(content), "bytes": content})
    path.write_bytes(bytes(blob))
    return out


# -- exFAT -------------------------------------------------------------------

def _exfat_ts(dt: datetime) -> int:
    return ((dt.year - 1980) << 25) | (dt.month << 21) | (dt.day << 16) | (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)


def _exfat_set(name: str, is_dir: bool, cluster: int, size: int, dt: datetime, tz_quarters: int,
               deleted: bool = False) -> bytes:
    units = name.encode("utf-16-le")
    n_name = -(-len(name) // 15)
    tz = 0x80 | (tz_quarters & 0x7F)
    primary = bytearray(32)
    primary[0] = 0x85
    primary[1] = 1 + n_name
    struct.pack_into("<H", primary, 4, 0x10 if is_dir else 0x20)
    ts = _exfat_ts(dt)
    struct.pack_into("<III", primary, 8, ts, ts, ts)
    primary[22] = primary[23] = primary[24] = tz
    stream = bytearray(32)
    stream[0] = 0xC0
    stream[1] = 0x03                      # allocation possible, no FAT chain (contiguous)
    stream[3] = len(name)
    struct.pack_into("<Q", stream, 8, size)
    struct.pack_into("<I", stream, 20, cluster)
    struct.pack_into("<Q", stream, 24, size)
    out = bytearray(primary + stream)
    for i in range(n_name):
        e = bytearray(32)
        e[0] = 0xC1
        part = units[i * 30: (i + 1) * 30]
        e[2: 2 + len(part)] = part
        out += e
    if deleted:
        for i in range(0, len(out), 32):
            out[i] &= 0x7F
    return bytes(out)


def build_exfat_stick(path: Path, label: str, folder: str, files: list[tuple[str, bytes]],
                      written: datetime, deleted: list[tuple[str, bytes]] = (), tz_quarters: int = -16) -> None:
    sector, spc = 512, 8
    cluster = sector * spc
    fat_off, fat_len, heap_off, count = 128, 64, 256, 6000
    img = bytearray((heap_off + count * spc) * sector)
    vbr = bytearray(512)
    vbr[0:3] = b"\xeb\x76\x90"
    vbr[3:11] = b"EXFAT   "
    struct.pack_into("<IIIII", vbr, 80, fat_off, fat_len, heap_off, count, 4)
    vbr[108], vbr[109] = 9, 3
    vbr[510:512] = b"\x55\xaa"
    img[0:512] = vbr

    def coff(c: int) -> int:
        return heap_off * sector + (c - 2) * cluster

    def set_fat(c: int, value: int) -> None:
        struct.pack_into("<I", img, fat_off * sector + c * 4, value)

    for c in (2, 3, 4):                    # bitmap, up-case table, root directory
        set_fat(c, 0xFFFFFFFF)
    root = bytearray()
    lab = bytearray(32)
    lab[0] = 0x83
    lab[1] = len(label)
    lab[2: 2 + len(label) * 2] = label.encode("utf-16-le")
    root += lab
    bitmap = bytearray(32)
    bitmap[0] = 0x81
    struct.pack_into("<IQ", bitmap, 20, 2, cluster)
    root += bitmap
    upcase = bytearray(32)
    upcase[0] = 0x82
    struct.pack_into("<IQ", upcase, 20, 3, cluster)
    root += upcase
    sub_cluster = 5
    root += _exfat_set(folder, True, sub_cluster, cluster, written, tz_quarters)
    img[coff(4): coff(4) + len(root)] = root

    sub = bytearray()
    nxt = 6
    for name, content in list(files) + [(n, c) for n, c in deleted]:
        is_deleted = (name, content) in list(deleted)
        img[coff(nxt): coff(nxt) + len(content)] = content
        sub += _exfat_set(name, False, nxt, len(content), written, tz_quarters, deleted=is_deleted)
        nxt += -(-len(content) // cluster)
    img[coff(sub_cluster): coff(sub_cluster) + len(sub)] = sub
    path.write_bytes(bytes(img))


# -- UDF write-once disc -----------------------------------------------------

def _udf_tag(ident: int, location: int) -> bytearray:
    tag = bytearray(16)
    struct.pack_into("<HH", tag, 0, ident, 2)
    struct.pack_into("<I", tag, 12, location)
    tag[4] = (sum(tag[0:4]) + sum(tag[5:16])) & 0xFF
    return tag


def _udf_time(dt: datetime, tz_minutes: int = -240) -> bytes:
    return struct.pack("<HhBBBBBBBB", (1 << 12) | (tz_minutes & 0x0FFF), dt.year, dt.month, dt.day,
                       dt.hour, dt.minute, dt.second, 0, 0, 0)


def _udf_fid(name: str, icb_block: int, location: int, parent: bool = False, is_dir: bool = False) -> bytes:
    ident = b"" if parent else b"\x08" + name.encode("latin-1")
    body = bytearray(38 + len(ident))
    body[0:16] = _udf_tag(257, location)
    struct.pack_into("<H", body, 16, 1)
    body[18] = (0x08 | 0x02) if parent else (0x02 if is_dir else 0x00)
    body[19] = len(ident)
    struct.pack_into("<II", body, 20, 2048, icb_block)
    body[38:] = ident
    body += b"\x00" * (-len(body) % 4)
    return bytes(body)


def _udf_file_entry(location: int, size: int, data_block: int, written: datetime) -> bytes:
    fe = bytearray(2048)
    fe[0:16] = _udf_tag(261, location)
    fe[27] = 5                                            # regular file
    struct.pack_into("<H", fe, 34, 0)                     # short allocation descriptors
    struct.pack_into("<Q", fe, 56, size)
    fe[72:84] = _udf_time(written)
    fe[84:96] = _udf_time(written)
    struct.pack_into("<II", fe, 168, 0, 8)
    struct.pack_into("<II", fe, 176, size, data_block)
    return bytes(fe)


def build_udf_disc(path: Path, kept: list[tuple[str, bytes]], removed: list[tuple[str, bytes]],
                   written: datetime) -> None:
    """A write-once disc: an old directory lists everything, the newest lists only `kept`."""
    S = 2048
    part = 64
    blocks: dict[int, bytes] = {}
    for i, ident in enumerate((b"BEA01", b"NSR02", b"TEA01")):
        blocks[16 + i] = b"\x00" + ident + b"\x01"
    pd = bytearray(S)
    pd[0:16] = _udf_tag(5, 32)
    struct.pack_into("<I", pd, 188, part)
    blocks[32] = bytes(pd)

    everything = list(removed) + list(kept)
    fe_block = 10
    data_block = 40
    entries = {}
    for name, content in everything:
        blocks[part + fe_block] = _udf_file_entry(fe_block, len(content), data_block, written)
        blocks[part + data_block] = content
        entries[name] = fe_block
        fe_block += 1
        data_block += -(-len(content) // S) + 1
    old = bytearray(_udf_fid("", 1, 2, parent=True))
    for name, _ in everything:
        old += _udf_fid(name, entries[name], 2)
    new = bytearray(_udf_fid("", 1, 3, parent=True))
    for name, _ in kept:
        new += _udf_fid(name, entries[name], 3)
    blocks[part + 2] = bytes(old)
    blocks[part + data_block + 4] = bytes(new)        # the newest directory sits after the data
    last = max(blocks) + 8
    img = bytearray(last * S)
    for sector, content in blocks.items():
        img[sector * S: sector * S + len(content)] = content
    path.write_bytes(bytes(img))


# -- the practice case -------------------------------------------------------

CASE_ID = "halcyon-practice"


def _triage(d1: str, d2: str, d3: str, renames: list[tuple[str, str]]) -> list[dict]:
    hist = "Chrome history database"
    ev = [
        {"time": f"{d1}T13:12:40", "kind": "web_search", "title": 'Searched Google for "how to copy company files without being noticed"',
         "summary": "The user searched Google in Chrome.", "source": hist, "severity": 3,
         "data": {"query": "how to copy company files without being noticed", "engine": "Google"}},
        {"time": f"{d1}T13:15:02", "kind": "web_search", "title": 'Searched Google for "does IT monitor usb drives"',
         "summary": "The user searched Google in Chrome.", "source": hist, "severity": 2,
         "data": {"query": "does IT monitor usb drives", "engine": "Google"}},
        {"time": f"{d1}T13:16:30", "kind": "web_search", "title": 'Searched Google for "change file extension hide document"',
         "summary": "The user searched Google in Chrome.", "source": hist, "severity": 3,
         "data": {"query": "change file extension hide document", "engine": "Google"}},
        {"time": f"{d1}T14:31:10", "kind": "usb_connected", "title": "USB device HALCYON SECURE first connected",
         "summary": "The company-issued stick was plugged in for the first time on this computer.",
         "source": "SYSTEM registry hive: USBSTOR", "device": "usb1", "severity": 2, "detail": "serial 5A1100349921",
         "data": {"serial": "5A1100349921", "event": "first_insert"}},
        {"time": f"{d1}T14:37:20", "kind": "file_opened", "title": "Opened kestrel_roadmap.docx",
         "summary": "E:\\Project Kestrel\\kestrel_roadmap.docx was opened from the company stick.",
         "source": "Windows shortcut file", "path": "C:\\Users\\rvance\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\kestrel_roadmap.lnk",
         "severity": 2, "data": {"name": "kestrel_roadmap.docx", "target": "E:\\Project Kestrel\\kestrel_roadmap.docx"}},
        {"time": f"{d2}T09:38:05", "kind": "usb_connected", "title": "USB device HALCYON SECURE connected (most recent)",
         "summary": "The company-issued stick was plugged in again.", "source": "SYSTEM registry hive: USBSTOR",
         "device": "usb1", "severity": 2, "detail": "serial 5A1100349921", "data": {"serial": "5A1100349921", "event": "last_insert"}},
    ]
    t = datetime.fromisoformat(f"{d2}T09:50:10")
    for i, (old, new) in enumerate(renames):
        when = t.replace(second=(10 + i * 7) % 60, minute=50 + (10 + i * 7) // 60)
        ev.append({"time": when.isoformat(), "kind": "file_renamed", "title": f"Renamed {old} to {new}",
                   "summary": f"C:\\Users\\rvance\\Desktop\\tmp\\{old} was renamed to {new}. The extension changed.",
                   "source": "$UsnJrnl:$J", "path": f"C:\\Users\\rvance\\Desktop\\tmp\\{new}", "detail": f"was {old}",
                   "severity": 3, "tags": ["rename", "extension-change"],
                   "data": {"old_name": old, "new_name": new, "name": new}})
    ev += [
        {"time": f"{d2}T09:58:12", "kind": "usb_connected", "title": "USB device VANCE first connected",
         "summary": "A second, personal stick was plugged in for the first time.", "source": "SYSTEM registry hive: USBSTOR",
         "device": "usb2", "severity": 2, "detail": "serial 7C4400120583", "data": {"serial": "7C4400120583", "event": "first_insert"}},
        {"time": f"{d2}T16:49:30", "kind": "program_executed", "title": "Ran IMGBURN.EXE",
         "summary": "A disc burning program was started.", "source": "Windows Prefetch", "program": "ImgBurn",
         "path": "C:\\Windows\\Prefetch\\IMGBURN.EXE-2A3C9D11.pf", "severity": 2, "data": {"name": "IMGBURN.EXE"}},
        {"time": f"{d2}T17:06:40", "kind": "web_search", "title": 'Searched Google for "can security scan a cd at the exit"',
         "summary": "The user searched Google in Chrome.", "source": hist, "severity": 2,
         "data": {"query": "can security scan a cd at the exit", "engine": "Google"}},
        {"time": f"{d3}T10:46:44", "kind": "web_search", "title": 'Searched Google for "anti-forensic tools"',
         "summary": "The user searched Google in Chrome.", "source": hist, "severity": 3,
         "data": {"query": "anti-forensic tools", "engine": "Google"}},
        {"time": f"{d3}T10:46:58", "kind": "web_search", "title": 'Searched Google for "eraser secure delete"',
         "summary": "The user searched Google in Chrome.", "source": hist, "severity": 3,
         "data": {"query": "eraser secure delete", "engine": "Google"}},
        {"time": f"{d3}T10:47:34", "kind": "web_download", "title": "Downloaded Eraser 6.2.0.2962.exe",
         "summary": "Eraser 6.2.0.2962.exe was downloaded.", "source": "Chrome download history",
         "path": "C:\\Users\\rvance\\Downloads\\Eraser 6.2.0.2962.exe", "severity": 2,
         "data": {"name": "Eraser 6.2.0.2962.exe", "url": "https://downloads.example/eraser"}},
        {"time": f"{d3}T10:50:14", "kind": "program_installed", "title": "Installed Eraser 6.2.0.2962",
         "summary": "Eraser 6.2.0.2962 was installed.", "source": "SOFTWARE registry hive: Uninstall", "program": "Eraser",
         "severity": 3, "data": {"name": "Eraser 6.2.0.2962"}},
        {"time": f"{d3}T11:13:30", "kind": "program_executed", "title": "Ran ERASER.EXE",
         "summary": "ERASER.EXE was started (run count 1).", "source": "Windows Prefetch", "program": "Eraser",
         "path": "C:\\Windows\\Prefetch\\ERASER.EXE-6BE1C2A0.pf", "severity": 3, "data": {"name": "ERASER.EXE"}},
    ]
    for i, name in enumerate(("kestrel_notes.docx", "handover_list.xlsx", "exit_checklist.docx")):
        ev.append({"time": f"{d3}T11:13:{39 + i * 6}", "kind": "file_wiped", "title": f"{name} was overwritten and deleted",
                   "summary": f"C:\\Users\\rvance\\Desktop\\tmp\\{name} was renamed 7 times to meaningless names within "
                              "4 seconds and then deleted. Secure erasers do this to hide the file name after "
                              "overwriting the content.",
                   "source": "$UsnJrnl:$J", "path": f"C:\\Users\\rvance\\Desktop\\tmp\\{name}", "severity": 3,
                   "tags": ["wiped", "anti-forensics"], "data": {"name": name, "renames": 7}})
    ev += [
        {"time": f"{d3}T11:15:50", "kind": "program_executed", "title": "Ran CCLEANER64.EXE",
         "summary": "CCLEANER64.EXE was started (run count 1).", "source": "Windows Prefetch", "program": "CCleaner",
         "path": "C:\\Windows\\Prefetch\\CCLEANER64.EXE-90D1E4F2.pf", "severity": 3, "data": {"name": "CCLEANER64.EXE"}},
        {"time": f"{d3}T11:18:29", "kind": "program_uninstalled", "title": "Uninstalled CCleaner",
         "summary": "CCleaner was removed from the computer three minutes after it ran.",
         "source": "Application event log", "program": "CCleaner", "severity": 2, "data": {"name": "CCleaner"}},
    ]
    return ev


def build_practice_case(store: CaseStore, data_dir: Path) -> Case:
    """Create the Halcyon practice case and its four evidence items."""
    data_dir.mkdir(parents=True, exist_ok=True)
    d1, d2, d3 = "2025-09-15", "2025-09-16", "2025-09-17"
    docs = {
        "kestrel_design_review.pptx": make_pptx("Project Kestrel: design review (confidential)"),
        "kestrel_pricing_model.xlsx": make_xlsx("Project Kestrel pricing model (confidential)"),
        "kestrel_roadmap.docx": make_docx("Project Kestrel roadmap 2026 (confidential)"),
        "kestrel_test_results.xls": make_ole2("Workbook", 40, fill=11),
        "kestrel_supplier_terms.docx": make_docx("Project Kestrel supplier terms (confidential)"),
        "kestrel_board_brief.ppt": make_ole2("PowerPoint Document", 90, fill=77),
    }
    disguise = {
        "kestrel_design_review.pptx": ("pics", "holiday_photos.zip"),
        "kestrel_pricing_model.xlsx": ("music", "mixtape_03.mp3"),
        "kestrel_roadmap.docx": ("misc", "recipe_book.pdf"),
        "kestrel_test_results.xls": ("misc", "game_save.db"),
        "kestrel_supplier_terms.docx": ("pics", "wallpaper.png"),
        "kestrel_board_brief.ppt": ("music", "ringtone.amr"),
    }
    types = {"pptx": "PPTX", "xlsx": "XLSX", "docx": "DOCX", "xls": "XLS", "ppt": "PPT"}

    usb1 = data_dir / "usb_company.dd"
    build_exfat_stick(usb1, "HALCYON SECURE", "Project Kestrel", list(docs.items()),
                      datetime.fromisoformat(f"{d1}T09:12:30"),
                      deleted=[("kestrel_exit_plan.docx", make_docx("Exit plan: what to take and when"))])

    usb2 = data_dir / "usb_personal.dd"
    folders: dict[str, list] = {"pics": [], "music": [], "misc": []}
    for real, (folder, fake) in disguise.items():
        folders[folder].append((fake, docs[real], types[real.rsplit(".", 1)[1]]))
    build_formatted_stick(usb2, folders, label=b"VANCE      ",
                          copied=datetime.fromisoformat(f"{d2}T09:58:40"),
                          formatted=datetime.fromisoformat(f"{d2}T17:02:10"),
                          stray=make_docx("Kestrel contact list: who to call at the buyer"))

    disc = data_dir / "disc_cdr.iso"
    burned = ["kestrel_design_review.pptx", "kestrel_roadmap.docx", "kestrel_board_brief.ppt", "kestrel_pricing_model.xlsx"]
    build_udf_disc(disc, kept=[("beach.png", make_png(1)), ("team_photo.png", make_png(2))],
                   removed=[(disguise[n][1], docs[n]) for n in burned],
                   written=datetime.fromisoformat(f"{d2}T16:54:20"))

    triage = data_dir / "workstation_triage.jsonl"
    renames = [(real, fake) for real, (_, fake) in disguise.items()]
    triage.write_text("# Synthetic triage export for the Halcyon practice case. One artifact record per line.\n"
                      + "\n".join(json.dumps(e) for e in _triage(d1, d2, d3, renames)) + "\n")

    case = Case(
        id=CASE_ID, name="Halcyon Robotics: Project Kestrel leak (practice case)", timezone="America/New_York",
        description=("Synthetic practice case. An engineer is suspected of taking Project Kestrel documents "
                     "before resigning. Evidence: a company USB stick, a personal USB stick, a CD-R found at "
                     "the exit, and a triage export from the workstation. All data is generated."),
        images=[
            ImageRef("pc", str(triage), "Workstation (triage export)", "triage", notes="artifact export, not a disk image"),
            ImageRef("usb1", str(usb1), "Company USB stick", "usb", notes="HALCYON SECURE 5A1100349921"),
            ImageRef("usb2", str(usb2), "Personal USB stick", "usb", notes="VANCE 7C4400120583"),
            ImageRef("disc", str(disc), "CD-R from the exit", "optical"),
        ],
        people=[{"name": "R. Vance", "role": "engineer under suspicion (fictional)"}],
        synthetic=True,
    )
    store.save_case(case)
    return case
