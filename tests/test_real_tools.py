"""Cross-check against file systems written by standard tools, not by our own generator.

FAT32 comes from mkfs.vfat and mtools, then gets reformatted the way a quick format does.
UDF comes from genisoimage. The tests skip when those tools are not installed.
"""
import hashlib
import shutil
import subprocess

import pytest

from casereplay import fat32, synth, udf
from casereplay.carve import carve
from casereplay.images import find_volumes, open_image
from casereplay.magic import check_disguise, sniff

need = lambda *tools: pytest.mark.skipif(any(shutil.which(t) is None for t in tools), reason="tool not installed")

FILES = {
    "design/winter_storm.amr": lambda: synth.make_ole2("PowerPoint Document", 120),
    "design/winter_whether_advisory.zip": lambda: synth.make_pptx("detailed design"),
    "pricing decision/new_years_day.jpg": lambda: synth.make_xlsx("market analysis"),
    "proposal/landscape.png": lambda: synth.make_docx("proposal " * 4000),
    "proposal/a_gift_from_you.gif": lambda: synth.make_docx("detailed proposal"),
}


@pytest.fixture(scope="module")
def tree(tmp_path_factory):
    root = tmp_path_factory.mktemp("src") / "Secret Project Data"
    content = {}
    for rel, make in FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        data = make()
        p.write_bytes(data)
        content[p.name] = data
    return root, content


@need("mkfs.vfat", "mcopy")
def test_recovery_after_real_reformat(tree, tmp_path):
    root, content = tree
    img = tmp_path / "stick.img"
    with img.open("wb") as f:
        f.truncate(300 * 1024 * 1024)
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)
    run("mkfs.vfat", "-F", "32", "-n", "IAMAN", str(img))
    run("mcopy", "-s", "-i", str(img), str(root), "::/")
    run("mkfs.vfat", "-F", "32", "-n", "IAMAN $_@", str(img))          # the quick format

    fh = open_image(img)
    assert find_volumes(fh)[0].fstype == "FAT32"
    v = fat32.Fat32Volume(fh)
    assert v.volume_label_entry().name == "IAMAN $_@"
    assert not [e for e in v.walk_live()]                               # the stick looks empty
    got = {e.name: v.read_file(e) for e in v.iter_recoverable(v.scan_orphan_directories())}
    assert set(got) == set(content)
    for name, data in content.items():
        assert hashlib.sha256(got[name]).hexdigest() == hashlib.sha256(data).hexdigest(), name
        assert check_disguise(name, sniff(got[name])), name
    assert sorted(c.size for c in carve(fh)) == sorted(len(d) for d in content.values())


@need("genisoimage")
def test_udf_names_and_content(tree, tmp_path):
    root, content = tree
    flat = tmp_path / "disc"
    flat.mkdir()
    for name, data in content.items():
        (flat / name).write_bytes(data)
    iso = tmp_path / "disc.iso"
    subprocess.run(["genisoimage", "-quiet", "-udf", "-o", str(iso), str(flat)], check=True, capture_output=True)
    fh = open_image(iso)
    assert find_volumes(fh)[0].fstype == "UDF"
    s = udf.scan(fh)
    assert s.visible_names() == set(content)
    for name, data in content.items():
        fe = udf.entry_for(s, name)
        assert fe and fe.size == len(data) and fe.modified is not None
        assert udf.read_file(fh, s, fe) == data
