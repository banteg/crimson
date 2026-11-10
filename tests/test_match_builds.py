from __future__ import annotations

import json
from copy import deepcopy
from itertools import pairwise
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from crimson_re import match as matchlib
from crimson_re import match_builds
from crimson_re.cli.match import match_app

REGISTRY = match_builds.load_registry()
MAPPED_IMAGES = match_builds.mapped_images(REGISTRY)


def test_build_map_generates_freeware_donor_before_consumers() -> None:
    order = [(image.build, image.name) for image in match_builds.mapped_images(REGISTRY)]
    for build in ("1.0.2", "1.3.0"):
        assert order.index(("1.4.0", "crimson.exe")) < order.index((build, "crimson.exe"))
        assert order.index((build, "grim.dll")) < order.index((build, "crimson.exe"))


def test_native_map_does_not_identify_code_as_extended_string_literals() -> None:
    def caller(callee: bytes):
        # The direct call at 0x401000 references relinked x86 bytes. Both byte
        # sequences also happen to be valid, differing UTF-16/Latin-1 strings.
        code = bytes.fromhex("e8fb0f0000c3")
        mapped = b"\0" * 0x1000 + code + b"\0" * (0x1000 - len(code)) + callee
        image = matchlib.LoadedImage(mapped, 0x400000, len(mapped))
        return match_builds._body(image, 0x401000, len(code))

    first = caller(bytes.fromhex("55c3 6100 0000"))
    second = caller(bytes.fromhex("55c3 6200 0000"))
    assert first.signature == second.signature
    assert first.signature[0][1] == ((),)


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


@pytest.mark.parametrize("invalid", ["body", "overlap"])
def test_reviewed_historical_map_rejects_unbound_evidence(recovered_198_map, invalid: str) -> None:
    image, canonical, payload, original = recovered_198_map
    recovery = deepcopy(original)
    if invalid == "body":
        recovery["functions"][0]["body_sha256"] = "0" * 64
    else:
        payload["functions"].append({"name": "interior_false_positive", "address": "0x0041FC21", "end": "0x0041FC22"})
    with pytest.raises(ValueError):
        match_builds.apply_recovered_map(image, canonical, payload, recovery)


def test_reviewed_data_rejection_preserves_crt_tables_and_alternate_placements() -> None:
    image = REGISTRY.image("1.0.2", "crimson.exe")
    if not image.path.is_file():
        pytest.skip("pinned freeware executable unavailable")
    donor = REGISTRY.canonical(image)
    pins = json.loads((image.map_dir / "recovered.json").read_text())["rejected_data_placements"]
    pin = next(row for row in pins if row["name"] == "sprite_effect_pool")
    receipt = {"schema": 1, "sha256": image.sha256, "rejected_data_placements": [pin]}
    data = json.loads(image.target.data_map_path.read_text())
    assert all(row["name"] != pin["name"] for row in data["entries"])
    assert {row["name"] for row in data["entries"] if row["address"] == pin["address"]} == {
        "__pow10pos", "crt_pow10_positive",
    }

    candidate = {"name": pin["name"], "address": pin["address"], "program": image.target.image_name}
    payload: dict[str, Any] = {"data": {"entries": [*data["entries"], candidate], "notes": ""}, "functions": [], "summary": {}}
    with pytest.raises(ValueError, match="invalid rejected data placement evidence"):
        match_builds.apply_recovered_map(image, donor, deepcopy(payload), {
            **receipt, "rejected_data_placements": [{**pin, "sha256": "0" * 64}],
        })
    corrected = deepcopy(payload)
    match_builds.apply_recovered_map(image, donor, corrected, receipt)
    assert corrected["data"]["entries"] == data["entries"]

    candidate["address"] = "0x00422000"
    match_builds.apply_recovered_map(image, donor, payload, receipt)
    assert candidate in payload["data"]["entries"]


@pytest.mark.parametrize(("version", "flag"), [
    ("1.0.2", "freeware_level_up_reset_byte"), ("1.3.0", "freeware_logo_visible"), ("1.4.0", "freeware_logo_visible"),
])
def test_disproved_sse_bss_placement_requires_pinned_game_writes(version: str, flag: str) -> None:
    image = REGISTRY.image(version, "crimson.exe")
    if not image.path.is_file():
        pytest.skip("pinned freeware executable unavailable")
    donor = REGISTRY.canonical(image)
    recovery = json.loads((image.map_dir / "recovered.json").read_text())
    pin = next(row for row in recovery["rejected_data_placements"] if row["name"] == "d3dx_sse_math_bss")
    data = json.loads(image.target.data_map_path.read_text())
    locations = {r["name"]: r["address"] for r in data["entries"]}
    assert locations[flag] == pin["address"] and pin["name"] not in locations

    candidate = {"name": pin["name"], "address": pin["address"], "program": image.target.image_name}
    payload = {"data": {"entries": [candidate], "notes": ""}, "functions": [], "summary": {}}
    # The original bytes are all zero at these locations. Removing the
    # separately anchored game flag must prevent the map correction.
    native = [r for r in recovery["data"] if r["name"] in pin["conflicting_globals"] and r["name"] != flag]
    receipt = {"schema": 1, "sha256": image.sha256, "data": native, "rejected_data_placements": [pin]}
    with pytest.raises(ValueError, match="missing conflicting native global"):
        match_builds.apply_recovered_map(image, donor, payload, receipt)


def test_chained_recovery_checks_root_identities_missing_from_donor() -> None:
    image = REGISTRY.image("1.3.0", "crimson.exe")
    if not image.path.is_file():
        pytest.skip("pinned historical executable unavailable")
    donor = REGISTRY.canonical(image)
    root = REGISTRY.identity(image)
    donor_names = {row["name"] for row in json.loads(donor.target.functions_path.read_text())}
    root_manifest = matchlib.load_function_manifest(
        root.target.functions_path, metadata_path=root.target.metadata_path, image_name=root.target.image_name, scope="all",
    )
    missing = [function for function in root_manifest.functions if function.name not in donor_names]
    # A changed intermediate map must not invalidate a reviewed absence or
    # strip a pinned root identity from a function independently found here.
    receipt = json.loads((image.map_dir / "recovered.json").read_text())
    pin = {**receipt["functions"][0], "name": missing[0].name}
    payload = {"functions": [{"name": missing[1].name}], "data": {"entries": [], "notes": ""}, "summary": {}}
    match_builds.apply_recovered_map(image, donor, payload, {
        "schema": 1, "sha256": image.sha256, "functions": [pin], "absent": [{"name": missing[1].name}],
    })
    row, = payload["functions"]
    assert row["name"] == missing[0].name
    assert matchlib.parse_int(row["canonical_address"]) == missing[0].address


def test_build_only_scratch_stays_out_of_other_compiler_and_report_runs(tmp_path: Path) -> None:
    # Restrict a known function in this fixture; production scratches can gain
    # matching source for more builds as recovery advances.
    scratch = tmp_path / "scratches" / "player_check_level"
    scratch.mkdir(parents=True)
    (scratch / "scratch.conf").write_text("FUNCTION=player_check_level\nBUILDS=1.4.0\n")
    config = matchlib.load_scratch_config(scratch)
    assert not matchlib._filter_scoped_scratch_configs([config], scope="all")
    assert REGISTRY.image("1.4.0", "crimson.exe").scratch_configs(config)
    assert not REGISTRY.image("1.3.0", "crimson.exe").scratch_configs(config)
    assert match_builds.scan_build(REGISTRY, "1.0.2", tmp_path) == []
    with pytest.raises(ValueError, match="configured only for"):
        REGISTRY.image("1.9.93", "crimsonland.exe").scratch_config(config)


def test_reviewed_build_only_function_requires_an_explicit_byte_pin(recovered_198_map) -> None:
    image, canonical, payload, original = recovered_198_map
    recovery = deepcopy(original)
    pin = recovery["functions"][0]
    # Replace a known placement with a local identity for the same bytes.
    payload["functions"] = [row for row in payload["functions"] if row["name"] != pin["name"]]
    pin["name"] = "local_gameplay_routine"
    with pytest.raises(ValueError, match="unknown recovered function"):
        match_builds.apply_recovered_map(image, canonical, deepcopy(payload), recovery)
    pin["build_only"] = True
    match_builds.apply_recovered_map(image, canonical, payload, recovery)
    row = next(row for row in payload["functions"] if row["name"] == pin["name"])
    assert row["build_only"] and "canonical_address" not in row
    assert row["evidence"] == "recovered"


@pytest.mark.parametrize("image", MAPPED_IMAGES, ids=lambda image: image.target.image_name)
def test_committed_build_maps_bind_canonical_names_to_the_pinned_image(image: match_builds.BuildImage) -> None:
    canonical = REGISTRY.canonical(image)
    target = image.target
    metadata = json.loads(target.metadata_path.read_text(encoding="utf-8"))
    assert (metadata["sha256"], metadata["canonical_sha256"]) == (image.sha256, canonical.sha256)

    identity = REGISTRY.identity(image).target
    canonical_addresses = {
        function.name: function.address
        for function in matchlib.load_function_manifest(
            identity.functions_path,
            metadata_path=identity.metadata_path,
            image_name=identity.image_name,
            scope="all",
        ).functions
    }
    rows = json.loads(target.functions_path.read_text(encoding="utf-8"))
    for row in rows:
        assert row["evidence"] in match_builds.EVIDENCE
        if row.get("build_only"):
            assert row["name"] not in canonical_addresses and "canonical_address" not in row
        else:
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


def test_historical_probe_applies_target_flags_to_override(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_evaluate(
        config: matchlib.ScratchConfig, *args: object, **kwargs: object,
    ) -> matchlib.ScratchStatus:
        return matchlib.ScratchStatus(config, 0x401000, 1, 1.0, 1, 1, 1, None)

    monkeypatch.setattr(matchlib, "evaluate_scratch", fake_evaluate)
    directory = matchlib.DEFAULT_MATCH_ROOT / "scratches/grim_get_fps"
    result = CliRunner().invoke(
        match_app, ["probe", str(directory), "--build", "1.9.8", "--cflags", "/O1 /MD", "--stdin", "--json"],
        input="float grim_get_fps(void) { return 1.0f; }",
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    for side in ("baseline", "probe"):
        assert payload[side]["cflags"] == "/O1 /MT /DCL_BUILD=10908"


def test_build_reference_aliases_apply_only_to_their_build() -> None:
    config = matchlib.load_scratch_config(matchlib.DEFAULT_MATCH_ROOT / "scratches/demo_purchase_screen_update")
    alias = ("$E4", "demo_purchase_already_paid_button_destroy")
    assert alias in dict(config.build_reference_aliases)[10908]
    assert alias not in config.reference_aliases
    assert alias in REGISTRY.image("1.9.8", config.image).scratch_config(config).reference_aliases


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
    # Equal sizes pair at the same position among the unpaired functions.
    assert match_builds._align([39, 8], [8, 8]) == [(1, 1)]
    # Leftover runs of equal length pair in order whatever their sizes (tail-jump wrappers).
    assert match_builds._fill_equal_runs([], 3, 3) == [(0, 0), (1, 1), (2, 2)]
    assert match_builds._fill_equal_runs([(0, 0), (3, 2)], 5, 4) == [(0, 0), (3, 2), (4, 3)]


def test_flow_extent_ends_at_reachable_code_and_skips_its_switch_table() -> None:
    code = bytes.fromhex(
        "83f801"  # cmp eax, 1
        "7707"  # ja 0x100c
        "ff248510100000"  # jmp [eax*4+0x1010]
        "c3"  # 0x100c: ret
        "cccccc"
        "0c1000000c100000"  # 0x1010: both cases reach the ret
        "33c0c3",  # 0x1018: the next function
    )
    image = matchlib.LoadedImage(code, 0x1000, len(code))
    assert match_builds._flow_extent(image, 0x1000, 0x1000 + len(code)) == (0x100D, 0x1018)


@pytest.fixture
def synthetic_mapper():
    code = bytes.fromhex("b8 78563412 b9 21436587 ba ccddffee c3")
    original = code + b"\xcc" * 16
    # Another build pads less and immediately starts an unrelated function.
    target = code + b"\x90" * 8 + bytes.fromhex("31 c0 c3") + b"\xcc" * 5
    mapper = match_builds._Mapper.__new__(match_builds._Mapper)
    mapper.pinned = {}
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
    return mapper


def test_body_search_ignores_verified_padding_without_reading_the_next_function(synthetic_mapper) -> None:
    mapper = synthetic_mapper
    mapper.search()
    assert mapper.hits == {0x1000: [0x2000]}
    assert mapper.accept(0x1000, 0x2000, "ordered")
    assert mapper.evidence[0x1000] == "exact"
    assert mapper.bodies[0x1000].size == 16


@pytest.mark.parametrize("pin", [(0x2000, 0x2010), (0x2008, 0x2018)])
def test_build_only_pin_protects_its_target_range_in_each_donor(synthetic_mapper, pin) -> None:
    mapper = synthetic_mapper
    mapper.pinned = {"only_in_target": pin}
    # Keep an identical body after the reviewed span. Only that copy can seed further matches.
    code = mapper.target.mapped * 2
    mapper.target = matchlib.LoadedImage(code, 0x2000, len(code))
    mapper.code = [(0x2000, code)]
    mapper.search()
    assert mapper.hits == {0x1000: [0x2020]}
    assert not mapper.accept(0x1000, pin[0] + 1, "referenced")
    assert not mapper.mapped
    mapper.entry_points = [0x2000, pin[0] + 1, 0x2020]
    assert mapper.boundaries() == sorted({0x2000, pin[0], 0x2020})
    mapper.starts = [0x1000]
    mapper.source_code, mapper.code_ranges = [(0x1000, 0x1020)], [(0x2000, 0x2040)]
    assert mapper.fill_by_order() == [0x1000]
    assert mapper.mapped == {0x1000: 0x2020}
    # When the only available layout slot belongs to the pin, the donor stays unmapped.
    mapper.mapped.clear()
    mapper.evidence.clear()
    mapper.hits.clear()
    mapper.entry_points = [pin[0] + 1]
    mapper.flows = {}
    assert not mapper.fill_by_order()
    assert not mapper.mapped


def test_build_only_pin_keeps_neighbouring_layout_positions(synthetic_mapper) -> None:
    mapper = synthetic_mapper
    mapper.pinned = {"only_in_target": (0x2000, 0x2010)}
    mapper.starts = [0x1000, 0x1010]
    mapper.bodies[0x1010] = mapper.bodies[0x1000]
    # Two changed 16-byte functions remain in order. The first target has its own local identity.
    code = (b"\x31\xc0" + b"\x90" * 13 + b"\xc3") * 2
    mapper.target = matchlib.LoadedImage(code, 0x2000, len(code))
    mapper.code = [(0x2000, code)]
    mapper.entry_points = [0x2000, 0x2010]
    mapper.source_code, mapper.code_ranges = [(0x1000, 0x1020)], [(0x2000, 0x2020)]
    mapper.flows = {}
    assert not mapper.fill_by_order()  # Neither body survived relinking.
    assert mapper.mapped == {0x1010: 0x2010}
    assert mapper.evidence == {0x1010: "ordered"}


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
    slots = match_builds._grim_slot_offsets("1.9.93", "1.9.8")
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
        (["mul ebx"], False),
        (["call ADDR"], False),
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


@pytest.mark.parametrize("build", ["1.0.2"])
def test_freeware_scratches_use_the_original_image_and_donor_maps(build: str) -> None:
    image = REGISTRY.image(build, "crimsonland.exe")
    assert image.name == "crimson.exe"
    # The freeware family maps its executables through 1.4.0; names still come from 1.9.93.
    assert image.canonical_build == "1.4.0"
    assert REGISTRY.canonical(image) == REGISTRY.image("1.4.0", "crimson.exe")
    assert REGISTRY.identity(image) == REGISTRY.image("1.9.93", "crimsonland.exe")
    assert image == REGISTRY.image(build, "crimson.exe")
    config = matchlib.load_scratch_config(matchlib.DEFAULT_MATCH_ROOT / "scratches/console_init")
    (built,) = image.scratch_configs(config)
    assert built.image == "crimson.exe"
    assert built.compiler == "msvc6.5"
    assert f"/DCL_BUILD={image.cl_build}" in built.cflags
    assert built.end_va is None
    assert image.target.image_path == image.path
    assert image.target.image_name == f"{build}/crimson.exe"


def test_order_candidates_inside_verified_bodies_cannot_split_functions() -> None:
    mapper = match_builds._Mapper.__new__(match_builds._Mapper)
    mapper.pinned = {}
    mapper.entry_points = [0x1000, 0x1030, 0x1040, 0x1050, 0x1060]
    mapper.mapped = {0x2000: 0x1000, 0x2100: 0x1040}
    mapper.evidence = {0x2000: "exact", 0x2100: "interface"}
    code = bytes.fromhex("90 " * 63 + "c3")
    mapper.bodies = {
        0x2000: match_builds._body(matchlib.LoadedImage(code, 0x2000, 64), 0x2000, 64),
        0x2100: match_builds._body(matchlib.LoadedImage(code[:31] + b"\xc3", 0x2100, 32), 0x2100, 32),
    }
    assert mapper.boundaries() == [0x1000, 0x1040, 0x1060]


FAMILY_LAYOUTS = sorted(
    path
    for path in (matchlib.REPO_ROOT / "decomp").glob("*/*/layout.json")
    if json.loads(path.read_text(encoding="utf-8"))["kind"] == "crimson-family-source-layout"
)


@pytest.mark.parametrize("layout_path", FAMILY_LAYOUTS, ids=lambda path: path.parent.name)
def test_family_layout_places_each_source_in_its_native_object(layout_path: Path) -> None:
    payload = json.loads(layout_path.read_text(encoding="utf-8"))
    root = (matchlib.REPO_ROOT / payload["root"]).resolve()
    assert root == layout_path.parent.resolve()
    image = REGISTRY.image(payload["build"], payload["image"])
    assert image.family == payload["family"]
    mapped = {
        row["name"]: int(row["address"], 16)
        for row in json.loads(image.target.functions_path.read_text(encoding="utf-8"))
    }
    family_builds = [
        build
        for build, images in REGISTRY.builds.items()
        if image.name in images and images[image.name].family == image.family
    ]
    seen: set[Path] = set()
    all_ranges: list[tuple[int, int]] = []
    for module in payload["modules"]:
        ranges = [(int(start, 16), int(end, 16)) for start, end in module["ranges"]]
        assert ranges == sorted(ranges)
        all_ranges.extend(ranges)
        for row in module["sources"]:
            source = (matchlib.REPO_ROOT / row["path"]).resolve()
            assert source.is_relative_to(root) and source.is_file() and source not in seen
            seen.add(source)
            for config_dir in row["configs"]:
                config = matchlib.load_scratch_config(matchlib.REPO_ROOT / config_dir)
                overrides = dict(config.family_sources)
                # The reference build defines object ranges. A source may be specific to another member.
                assert any(
                    (config.directory / overrides.get(build, overrides.get(payload["family"], config.source))).resolve()
                    == source
                    for build in family_builds if config.supports_build(build)
                )
                if config.function in mapped:
                    assert any(start <= mapped[config.function] < end for start, end in ranges)
    previous_end = 0
    for start, end in sorted(all_ranges):
        assert previous_end <= start < end
        previous_end = end
    assert seen == {path.resolve() for path in root.rglob("*") if path.suffix in {".c", ".cpp"}}
