from __future__ import annotations

import hashlib
import itertools
import json
import struct

import pytest

from crimson_re import match as matchlib
from crimson_re import match_builds
from crimson_re import match_freeware_library_data as library_data


def test_archive_data_requires_complete_initializer_and_relocation_proof() -> None:
    original = b"abcd" + struct.pack("<I", 2) + b"efgh"
    plan = {"anchor_offset": 0, "anchor_hex": b"abcd".hex(), "size": len(original),
            "sha256": hashlib.sha256(original).hexdigest(), "relocations": [[4, 2]]}
    va = 0x4000
    linked = b"abcd" + struct.pack("<I", va + 2) + b"efgh"
    regions = [(va, linked)]
    assert library_data._locate(plan, regions, {va + 4: 3}) == va
    assert library_data._locate(plan, regions, None) == va  # PE relocs stripped
    for relocs in ({}, {va + 4: 1}, {va - 1: 3, va + 4: 3}):
        assert library_data._locate(plan, regions, relocs) is None
    assert library_data._locate(plan, [(va, original)], None) is None
    assert library_data._locate(plan, [(va, linked[:-1] + b"i")], None) is None
    assert library_data._locate(plan, [(va, linked[:-1])], None) is None
    # Even an exact initializer in two distinct contributions leaves placement ambiguous.
    other = b"abcd" + struct.pack("<I", va + 0x102) + b"efgh"
    assert library_data._locate(plan, [*regions, (va + 0x100, other)], None) is None


@pytest.mark.parametrize(("version", "exe_bytes"), [("1.0.2", 9_608), ("1.3.0", 9_608), ("1.4.0", 9_000)])
def test_shipped_library_attributions_rebase_crt_heap_and_preserve_ownership(version: str, exe_bytes: int) -> None:
    paths = {name: im.path for name, im in match_builds.load_registry().builds[version].items()}
    if not all(path.is_file() for path in paths.values()):
        pytest.skip("pinned freeware image unavailable")
    evidence = json.loads((matchlib.REPO_ROOT / "analysis/decomp" / f"{version}.json").read_text())
    rows = library_data.attributions(version, paths, evidence["functions"])
    for image, size in {"crimson.exe": exe_bytes, "grim.dll": 25_066}.items():
        objects = [r for r in rows if r["image"] == image]
        assert all(r["owner"] == "libraries" for r in objects)
        assert sum(r["size"] for r in objects) == size
        assert all(a["address"] + a["size"] <= b["address"] for a, b in itertools.pairwise(objects))
        heap, = [r for r in objects if r["name"] == "sbheap.obj(.data)"]
        assert heap["size"] == 8_232 and len(heap["evidence"]["local_dir32"]) == 5
