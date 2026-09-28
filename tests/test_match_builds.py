from __future__ import annotations

import json
from itertools import pairwise

import pytest

from crimson import match as matchlib
from crimson import match_builds

REGISTRY = match_builds.load_registry()
MAPPED_IMAGES = match_builds.mapped_images(REGISTRY)


@pytest.mark.parametrize("image", MAPPED_IMAGES, ids=lambda image: image.target.image_name)
def test_committed_build_maps_bind_canonical_names_to_the_pinned_image(image: match_builds.BuildImage) -> None:
    canonical = REGISTRY.canonical(image)
    target = image.target
    metadata = json.loads(target.metadata_path.read_text(encoding="utf-8"))
    assert (metadata["sha256"], metadata["canonical_sha256"]) == (image.sha256, canonical.sha256)

    canonical_addresses = {
        function.name: function.address
        for function in matchlib.load_function_manifest(
            canonical.target.functions_path,
            metadata_path=canonical.target.metadata_path,
            image_name=canonical.target.image_name,
            scope="all",
        ).functions
    }
    rows = json.loads(target.functions_path.read_text(encoding="utf-8"))
    for row in rows:
        assert row["evidence"] in match_builds.EVIDENCE
        assert canonical_addresses[row["name"]] == int(row["canonical_address"], 16)
        assert int(row["end"], 16) - int(row["address"], 16) == row["size"] > 0
    for row, following in pairwise(rows):
        assert int(row["end"], 16) <= int(following["address"], 16)

    # The build's own rows name it; canonical name and data maps never apply.
    manifest = matchlib.load_function_manifest(
        target.functions_path,
        metadata_path=target.metadata_path,
        image_name=target.image_name,
    )
    assert {function.name: function.address for function in manifest.functions} == {
        row["name"]: int(row["address"], 16) for row in rows
    }
    entries = json.loads(target.data_map_path.read_text(encoding="utf-8"))["entries"]
    assert {entry["program"] for entry in entries} == {target.image_name}


def test_other_builds_compile_game_code_with_their_own_compiler_and_cl_build() -> None:
    config = matchlib.load_scratch_config(matchlib.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update")
    canonical = REGISTRY.image("1.9.93", config.image)
    processor_pack = REGISTRY.image("1.9.8", config.image)
    assert canonical.scratch_configs(config) == (config,)
    built = processor_pack.scratch_configs(config)
    assert [build_config.compiler for build_config in built] == list(processor_pack.profiles)
    assert {(build_config.cflags, build_config.end_va) for build_config in built} == {
        (f"{config.cflags} /DCL_BUILD={processor_pack.cl_build}", None),
    }


def test_prebuilt_libraries_keep_their_toolchain_in_other_builds() -> None:
    config = matchlib.load_scratch_config(matchlib.DEFAULT_MATCH_ROOT / "scratches/grim_adler32")
    assert config.compiler not in REGISTRY.image("1.9.93", config.image).game_profiles
    assert [built.compiler for built in REGISTRY.image("1.9.8", config.image).scratch_configs(config)] == [
        config.compiler,
    ]


def test_layout_alignment_skips_added_and_dropped_functions() -> None:
    # The target drops the 64-byte function and adds a 500-byte one.
    assert match_builds._align([100, 64, 300], [104, 500, 290]) == [(0, 0), (2, 2)]
    # One out-of-order anchor leaves the longest increasing run.
    assert match_builds._increasing([(1, 10), (2, 50), (3, 20), (4, 30)]) == [(1, 10), (3, 20), (4, 30)]
