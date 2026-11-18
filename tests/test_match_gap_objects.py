from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path

import pytest

from crimson_re import match, match_gap_objects


def _case():
    # The case label addresses the RET, two bytes into the function. The
    # original image has a linked pointer, the COFF field has a zero addend.
    image = match.LoadedImage(bytes.fromhex("89 c8 c3 90 02 10 00 00 01 90"), 0x1000, 10)
    owner = {"image": "game", "address": 0x1000, "end": 0x1003, "native_kind": "function",
             "name": "test", "ownership": "game", "matched": True, "candidate": "source",
             "proof": {"body_byte_exact": True, "candidate_object_sha256": "a" * 64}}
    gaps = [
        {"image": "game", "ownership": "game", "address": start, "end": end, "native_kind": kind,
         "gap_evidence": {"function": 0x1000, "type": evidence}}
        for start, end, kind, evidence in [
            (0x1003, 0x1004, "padding", "alignment"), (0x1004, 0x1008, "embedded_data", "switch_destinations"),
            (0x1008, 0x1009, "embedded_data", "switch_selectors"), (0x1009, 0x100A, "padding", "alignment"),
        ]
    ]
    receipt = {"image": "game", "function": 0x1000, "start": 0x1003, "end": 0x100A,
               "candidate_object_sha256": "a" * 64, "relocations": [0x1004],
               "sha256": hashlib.sha256(image.mapped[3:]).hexdigest()}
    data = b"\x90" * 4 + bytes.fromhex("89 c8 c3 90 00 00 00 00 01 90")
    obj = match.CoffObject(
        (match.CoffSection(".text", data, 0x20, (match.CoffRelocation(8, 1, match.IMAGE_REL_I386_DIR32),)),),
        (match.CoffSymbol(0, "_test", 4, 1, 0x20, match.IMAGE_SYM_CLASS_EXTERNAL),
         match.CoffSymbol(1, "$L1", 6, 1, 0, match.IMAGE_SYM_CLASS_LABEL)),
    )
    return image, [owner, *gaps], receipt, obj


def test_compiled_gap_requires_all_local_relocations_and_every_original_byte():
    image, _, receipt, obj = _case()
    match_gap_objects._check_object(obj, "test", image, receipt)
    section, = obj.sections
    function, target = obj.symbols
    corrupt = [
        (replace(obj, sections=(replace(section, relocations=()),)), "relocations differ"),
        (replace(obj, symbols=(function, replace(target, section_number=2))), "function-local"),
        (replace(obj, symbols=(function, replace(target, value=5))), "outside the function"),
        (replace(obj, sections=(replace(section, data=section.data[:-1]),)), "beyond its COFF"),
        (replace(obj, sections=(replace(section, data=section.data[:-1] + b"X"),)), "bytes differ"),
    ]
    for candidate, error in corrupt:
        with pytest.raises(ValueError, match=error):
            match_gap_objects._check_object(candidate, "test", image, receipt)


def test_saved_gap_receipts_reject_missing_coverage_and_changed_original_or_source(monkeypatch):
    image, inventory, receipt, _ = _case()
    monkeypatch.setattr(match, "load_image", lambda _: image)
    paths = {"game": Path("fixture.exe")}
    match_gap_objects.validate_tails(inventory, [receipt], paths)
    for invalid in ([], [receipt, receipt], [dict(receipt, sha256="b" * 64)],
                    [dict(receipt, candidate_object_sha256="c" * 64)], [dict(receipt, relocations=[])]):
        with pytest.raises(ValueError, match="gap object receipts differ"):
            match_gap_objects.validate_tails(inventory, invalid, paths)
    with pytest.raises(ValueError, match="missing selected source"):
        match_gap_objects.verify_tails(inventory, [], paths)
    inventory[0]["matched"] = False
    assert match_gap_objects.verify_tails(inventory, [], paths) == []
