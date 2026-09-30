from __future__ import annotations

import json
from copy import deepcopy
from itertools import pairwise

import pytest

from crimson_re import match as matchlib
from crimson_re import match_builds

REGISTRY = match_builds.load_registry()
MAPPED_IMAGES = match_builds.mapped_images(REGISTRY)


@pytest.fixture
def recovered_198_map():
    image = REGISTRY.image("1.9.8", "crimsonland.exe")
    if not image.path.is_file():
        pytest.skip("pinned historical executable unavailable")
    recovery = json.loads((image.map_dir / "recovered.json").read_text())
    payload = {
        "functions": json.loads(image.target.functions_path.read_text()),
        "data": json.loads(image.target.data_map_path.read_text()),
        "summary": {},
    }
    return image, REGISTRY.canonical(image), payload, recovery


def test_reviewed_historical_identities_retain_complete_extents_and_data(recovered_198_map) -> None:
    image, canonical, payload, recovery = recovered_198_map
    match_builds.apply_recovered_map(image, canonical, payload, recovery)
    rows = {row["name"]: row for row in payload["functions"]}
    assert (rows["projectile_spawn"]["size"], rows["weapon_table_init"]["size"]) == (390, 3974)
    assert rows["player_update"]["address"] == "0x00413C10"
    entries = {row["name"]: row["address"] for row in payload["data"]["entries"]}
    assert entries["player_state_table"] == "0x0048e5a0"
    assert entries["weapon_table"] == "0x004d4c74"
    # Identity evidence does not imply an instruction or encoded-body match.
    assert rows["projectile_spawn"]["evidence"] == "recovered"


@pytest.mark.parametrize("invalid", ["image", "body", "instruction", "operand", "name", "overlap"])
def test_reviewed_historical_map_rejects_unbound_evidence(recovered_198_map, invalid: str) -> None:
    image, canonical, payload, original = recovered_198_map
    recovery = deepcopy(original)
    if invalid == "image":
        recovery["sha256"] = "0" * 64
    elif invalid == "body":
        recovery["functions"][0]["body_sha256"] = "0" * 64
    elif invalid == "instruction":
        recovery["data"][0]["bytes"] = "00"
    elif invalid == "operand":
        recovery["data"][0]["address"] = "0x00484d20"
    elif invalid == "name":
        recovery["data"][0]["name"] = "unrecovered_identity"
    else:
        payload["functions"].append({"name": "interior_false_positive", "address": "0x0041FC21", "end": "0x0041FC22"})
    with pytest.raises(ValueError):
        match_builds.apply_recovered_map(image, canonical, payload, recovery)


def test_engine_maps_precede_the_game_interface_consumer() -> None:
    for build in {image.build for image in MAPPED_IMAGES}:
        assert [image.name for image in MAPPED_IMAGES if image.build == build] == ["grim.dll", REGISTRY.image(build, "crimsonland.exe").name]


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


def test_body_search_ignores_verified_padding_without_reading_the_next_function() -> None:
    code = bytes.fromhex("b8 78563412 b9 21436587 ba ccddffee c3")
    original = code + b"\xcc" * 16
    # Another build pads less and immediately starts an unrelated function.
    target = code + b"\x90" * 8 + bytes.fromhex("31 c0 c3") + b"\xcc" * 5
    mapper = match_builds._Mapper.__new__(match_builds._Mapper)
    mapper.source = matchlib.LoadedImage(original, 0x1000, len(original))
    mapper.target = matchlib.LoadedImage(target, 0x2000, len(target))
    function = matchlib.FunctionSymbol("example", 0x1000, 0x1020, 32)
    mapper.functions = [function]
    mapper.by_address = {function.address: function}
    mapper.bodies = {function.address: match_builds._body(mapper.source, function.address, function.size)}
    mapper.code = [(0x2000, target)]
    mapper.hits = {}
    mapper.mapped = {}
    mapper.evidence = {}
    mapper.grim_address = None
    mapper.grim_slots = {}
    mapper.search()
    assert mapper.hits == {0x1000: [0x2000]}
    assert mapper.accept(0x1000, 0x2000, "ordered")
    assert mapper.evidence[0x1000] == "exact"
    assert mapper.bodies[0x1000].size == len(code)


def test_cross_build_catalog_keeps_cpp_method_aliases() -> None:
    image = REGISTRY.image("1.9.8", "crimsonland.exe")
    catalog = match_builds._reference_catalog(image)
    assert catalog._addresses_for_symbol("??0console_queue_t@@QAE@XZ") == catalog._addresses_for_symbol("console_init")
    assert catalog.knows_name("??0console_queue_t@@QAE@XZ")


def test_cross_build_catalog_keeps_colocated_object_and_member_names() -> None:
    catalog = match_builds._reference_catalog(REGISTRY.image("1.9.8", "crimsonland.exe"))
    for base, member in (("effect_template", "effect_template_vel_x"), ("effect_pool", "effect_pool_pos_x")):
        assert catalog.knows_name(base)
        assert catalog._addresses_for_symbol(base) == catalog._addresses_for_symbol(member)


@pytest.mark.skipif(not REGISTRY.image("1.9.8", "grim.dll").path.is_file(), reason="requires pinned game images")
def test_198_virtual_slots_are_paired_from_the_actual_dll_vtables() -> None:
    assert REGISTRY.image("1.9.8", "grim.dll").state() == "ok"
    slots = match_builds._grim_slot_offsets("1.9.8")
    assert slots[0x4C] == 0x54  # flush input, after two legacy methods
    assert slots[0x114] == 0x10C  # set color, after removing four state-slot methods
    assert not {0x88, 0x8C, 0x90, 0x94} & slots.keys()


@pytest.mark.parametrize(
    ("middle", "expected"),
    [
        ([], True),
        (["push 0x3f800000"], True),
        (["mov ecx, ebx"], False),
        (["mov cl, 0x1"], False),
        (["imul edx, edx, 0x2"], False),
        (["mul ebx"], False),
        (["div ebx"], False),
        (["cdq"], False),
        (["xchg edx, ebx"], False),
        (["call ADDR"], False),
        (["jmp Lf"], False),
    ],
)
def test_virtual_slot_pairing_requires_the_grim_receiver_without_clobbers(middle: list[str], expected: bool) -> None:
    reference = matchlib.MaskedReference(1, "mem", "image", 0x480000, "grim_interface_ptr", (), True)
    lines = [
        matchlib.DisassemblyLine(0, 0, "mov ecx, dword [ADDR]", masked_references=(reference,)),
        matchlib.DisassemblyLine(5, 5, "mov edx, dword [ecx]"),
        *(matchlib.DisassemblyLine(10 + index * 5, 10 + index * 5, text) for index, text in enumerate(middle)),
        matchlib.DisassemblyLine(10 + len(middle) * 5, 10 + len(middle) * 5, "call dword [edx+0x114]"),
    ]
    body = match_builds._Body(tuple(lines), ())
    assert bool(match_builds._grim_virtual_calls(body, 0x480000)) is expected
    assert not match_builds._grim_virtual_calls(body, 0x490000)


@pytest.mark.parametrize("build", ["1.0.2", "1.3.0", "1.4.0"])
def test_freeware_scratches_use_the_original_image_and_donor_maps(build: str) -> None:
    image = REGISTRY.image(build, "crimsonland.exe")
    assert image.name == "crimson.exe"
    assert image.canonical_build is None
    assert REGISTRY.canonical(image) == REGISTRY.image("1.9.93", "crimsonland.exe")
    assert image == REGISTRY.image(build, "crimson.exe")
    config = matchlib.load_scratch_config(matchlib.DEFAULT_MATCH_ROOT / "scratches/console_init")
    built, = image.scratch_configs(config)
    assert built.image == "crimson.exe"
    assert built.compiler == "msvc6.5"
    assert f"/DCL_BUILD={image.cl_build}" in built.cflags
    assert built.end_va is None
    assert image.target.image_path == image.path
    assert image.target.image_name == f"{build}/crimson.exe"


def test_order_candidates_inside_verified_bodies_cannot_split_functions() -> None:
    mapper = match_builds._Mapper.__new__(match_builds._Mapper)
    mapper.entry_points = [0x1000, 0x1030, 0x1040, 0x1050, 0x1060]
    mapper.mapped = {0x2000: 0x1000, 0x2100: 0x1040}
    mapper.evidence = {0x2000: "exact", 0x2100: "interface"}
    code = bytes.fromhex("90 " * 63 + "c3")
    mapper.bodies = {
        0x2000: match_builds._body(matchlib.LoadedImage(code, 0x2000, 64), 0x2000, 64),
        0x2100: match_builds._body(matchlib.LoadedImage(code[:31] + b"\xc3", 0x2100, 32), 0x2100, 32),
    }
    assert mapper.boundaries() == [0x1000, 0x1040, 0x1060]
