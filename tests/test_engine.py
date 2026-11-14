import hashlib
from pathlib import Path

import pytest

from casereplay import fat32
from casereplay.carve import carve
from casereplay.images import find_volumes, open_image
from casereplay.magic import check_disguise, sniff

from .fixtures import build_disc, build_formatted_stick


@pytest.fixture(scope="module")
def stick(tmp_path_factory):
    p = tmp_path_factory.mktemp("img") / "stick.dd"
    return p, build_formatted_stick(p)


@pytest.fixture(scope="module")
def disc(tmp_path_factory):
    p = tmp_path_factory.mktemp("img") / "disc.raw"
    return p, build_disc(p)


def test_volume_detection(stick):
    path, _ = stick
    vols = find_volumes(open_image(path))
    assert vols[0].fstype == "FAT32"


def test_quick_format_leaves_empty_fat(stick):
    path, _ = stick
    v = fat32.Fat32Volume(open_image(path))
    assert v.fat_allocated_clusters() <= 1       # only the new root directory
    root = v.root_entries()
    assert len(root) == 1 and root[0].is_volume_label


def test_orphan_directories_recover_every_file(stick):
    path, truth = stick
    v = fat32.Fat32Volume(open_image(path))
    dirs = v.scan_orphan_directories()
    assert len(dirs) == 4                    # top folder plus three subfolders
    got = {e.name: e for e in v.iter_recoverable(dirs)}
    assert set(got) == {f["name"] for f in truth["files"]}
    for f in truth["files"]:
        e = got[f["name"]]
        data = v.read_file(e)
        assert hashlib.sha256(data).hexdigest() == hashlib.sha256(f["bytes"]).hexdigest()
        assert sniff(data) == f["type"]
        assert e.created == truth["copied"]
        assert f["dir"] in e.path


def test_disguise_is_flagged(stick):
    _, truth = stick
    for f in truth["files"]:
        hit = check_disguise(f["name"], f["type"])
        assert hit is not None, f["name"]
        assert hit["severity"] == 3
    assert check_disguise("report.docx", "DOCX") is None
    assert check_disguise("photo.jpg", "JPEG") is None


def test_carving_finds_the_stray_file(stick):
    path, truth = stick
    fh = open_image(path)
    found = list(carve(fh))
    hashes = {c.sha256 for c in found}
    assert hashlib.sha256(truth["stray"]).hexdigest() in hashes


def test_carving_sizes_are_exact(disc):
    path, truth = disc
    found = {c.offset: c for c in carve(open_image(path))}
    assert len(found) == len(truth)
    for f in truth:
        c = found[f["offset"]]
        assert c.size == f["size"], f["type"]
        assert c.type == f["type"]
        assert c.sha256 == hashlib.sha256(f["bytes"]).hexdigest()
