from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import replace

import pefile
import pytest

from crimson_re import match_builds
from crimson_re import match_freeware_data as inventory


@pytest.mark.parametrize(("version", "name", "total", "backed", "pe_bytes"), [
    ("1.0.2", "crimson.exe", 60_926, 24_486, 1834),
    ("1.0.2", "grim.dll", 64_825, 53_213, 3081),
    ("1.3.0", "crimson.exe", 135_166, 29_158, 2052),
    ("1.3.0", "grim.dll", 67_586, 53_934, 3081),
    ("1.4.0", "crimson.exe", 157_460, 33_340, 1898),
    ("1.4.0", "grim.dll", 68_514, 54_062, 3104),
])
def test_pinned_pe_virtual_bytes_are_partitioned_once(
    version: str, name: str, total: int, backed: int, pe_bytes: int,
) -> None:
    image = match_builds.load_registry().image(version, name)
    if not image.path.is_file():
        pytest.skip("pinned freeware image unavailable")
    evidence = inventory.build_evidence([image], [], [])
    spans = inventory.report_spans(evidence)
    with pefile.PE(str(image.path), fast_load=True) as pe:
        mapped = pe.get_memory_mapped_image()
        for section in evidence["sections"]:
            start, size = section["address"], section["size"]
            rva = start - pe.OPTIONAL_HEADER.ImageBase
            original = mapped[rva:rva + size]
            assert hashlib.sha256(original).hexdigest() == section["sha256"]
            cursor = start
            for span in (s for s in spans if s["section"] == section["name"]):
                assert span["address"] == cursor and span["size"] > 0
                cursor += span["size"]
            assert cursor == start + size
    counts = Counter()
    for s in spans:
        counts[s["status"]] += s["size"]
        counts[s["storage"]] += s["size"]
    assert counts == {"unattributed": total - pe_bytes, "pe-metadata": pe_bytes,
                      "file-backed": backed, "zero-fill": total - backed}
    assert {s["name"] for s in evidence["excluded_sections"]} == (
        {".text", ".rsrc", ".reloc"} if name == "grim.dll" else {".text", ".rsrc"}
    )


def test_overlapping_global_views_count_storage_once_and_unbounded_labels_claim_no_bytes() -> None:
    section = {"image": "sample", "name": ".data", "address": 0x1000, "size": 40, "file_size": 17}
    base = {"image": "sample", "owner": "game"}
    labels = [{**base, "address": 0x1000, "names": ["unbounded"]},
              {**base, "address": 0x1004, "names": ["array"], "size": 20}]
    first = {**base, "address": 0x1008, "size": 8, "name": "value", "source": "values.cpp"}
    alias = {**first, "address": 0x100c, "size": 8, "name": "alias"}
    library = [{**base, "owner": "libraries", "address": 0x1018, "size": 4, "name": "libword"}]
    metadata = [{"image": "sample", "address": 0x1000, "size": 2, "kind": "import-descriptors"}]
    spans = inventory._partition([section], labels, [first, alias], library, metadata)
    counts = Counter()
    for row in spans:
        counts[row["status"]] += row["size"]
    assert counts == {"source-matched": 12, "mapped-unmatched": 12, "pe-metadata": 2, "unattributed": 14}
    assert {s["address"] for s in spans if s["storage"] == "zero-fill"} == {0x1011, 0x1014, 0x1018, 0x101c}
    assert spans[0]["owner"] == "pe" and spans[1]["owner"] == "unknown"
    assert next(s for s in spans if s["address"] == 0x100c)["objects"] == ["alias", "array", "value"]


@pytest.mark.parametrize(("change", "reason"), [
    ("zero", "invalid freeware data extent"), ("boundary", "outside a unique PE"),
    ("image", "outside a unique PE"), ("owners", "conflicting freeware data owners"),
    ("metadata", "PE metadata overlaps"),
])
def test_freeware_data_rejects_ambiguous_or_historical_cross_image_storage(change: str, reason: str) -> None:
    section = {"image": "sample", "name": ".data", "address": 32, "size": 8, "file_size": 8}
    candidate = {"image": "sample", "address": 32, "size": 8, "name": "s", "source": "s.cpp", "owner": "game"}
    libraries = []
    metadata = []
    if change == "zero":
        candidate["size"] = 0
    if change == "boundary":
        candidate["size"] = 9
    if change == "image":
        candidate["image"] = "different"
    if change == "owners":
        libraries.append({**candidate, "owner": "libraries"})
    if change == "metadata":
        metadata.append({"image": "sample", "address": 32, "size": 4, "kind": "import-address-table"})
    with pytest.raises(ValueError, match=reason):
        inventory._partition([section], [], [candidate], libraries, metadata)


def test_freeware_data_rejects_wrong_original() -> None:
    image = match_builds.load_registry().image("1.0.2", "crimson.exe")
    if not image.path.is_file():
        pytest.skip("pinned freeware image unavailable")
    with pytest.raises(ValueError, match="registry pin"):
        inventory.build_evidence([replace(image, sha256="0" * 64)], [], [])
