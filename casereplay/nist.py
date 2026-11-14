"""The NIST CFReDS Data Leakage Case (2015), a public reference dataset.

https://cfreds-archive.nist.gov/data_leakage_case/data-leakage-case.html

Only what an investigator is handed goes in here: the image files and the
hashes NIST publishes next to them. Nothing from the answer key.
"""
from __future__ import annotations

from pathlib import Path

from .ledger import Case, CaseStore, ImageRef

CASE_ID = "nist-data-leakage"
IMAGES = [
    ("pc", "cfreds_2015_data_leakage_pc.E01", "Suspect PC", "computer", "72432916933F5A309A8C456B40C9601D1F8D2A4F"),
    ("rm1", "rm1.E01", "USB stick RM#1", "usb", "FFD0F3CBA3DFE3291F786B845A06A8AA56C1CD8C"),
    ("rm2", "rm2.E01", "USB stick RM#2", "usb", "2228554CD6FDD3C85BB80E0A0CD7F21A2364DC99"),
    ("rm3", "rm3_type3.E01", "CD-R RM#3", "optical", "75C106FDB2FD2F8068190E951589FF1F9860257E"),
]


def build_case(store: CaseStore, data_dir: Path) -> Case:
    images = [ImageRef(i, str(Path(data_dir) / name), label, kind, sha1_expected=sha)
              for i, name, label, kind, sha in IMAGES]
    try:
        old = {im.id: im for im in store.load_case(CASE_ID).images}
        for im in images:
            if im.id in old and old[im.id].path == im.path:
                im.sha1_actual = old[im.id].sha1_actual
    except FileNotFoundError:
        pass
    case = Case(
        id=CASE_ID, name="NIST CFReDS: Data Leakage Case", timezone="America/New_York",
        description=("Public reference case from NIST. An employee is suspected of leaking confidential "
                     "project files. Evidence: one Windows 7 PC image, two USB sticks and one CD-R."),
        images=images, reference="nist_ground_truth",
    )
    store.save_case(case)
    return case
