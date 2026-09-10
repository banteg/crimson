"""Verify ion-chain expression lifetimes with native creature-search execution."""

import argparse
import importlib.util
import json
import math
import struct
from dataclasses import asdict, replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE = HERE.parent / "plasma-head-alpha-2026-09-10" / "verify.py"
SPEC = importlib.util.spec_from_file_location("plasma_probe", ENGINE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
match = probe.match
POSITIONS = (
    ((125.5, 180.0), (100.0, 225.0)),
    ((80.75, 150.125), (155.3, 220.4)),
    ((111.25, 208.5), (111.25, 240.0)),
)
SCALES = {21: 2.2, 22: 1.05, 23: 3.5, 45: 0.8}


def creatures(positions):
    return (
        (0, 112.0, 209.0, 1, 16.0, 40.0),
        (1, *positions[0], 1, 16.0, 40.0),
        (2, *positions[1], 1, 16.0, 40.0),
        (3, 112.0, 209.0, 0, 16.0, 40.0),
        (4, 112.0, 209.0, 1, 4.0, 40.0),
        (5, 900.0, 900.0, 1, 16.0, 40.0),
        (6, 166.25, 208.5, 1, 16.0, 40.0),
    )


def execute(program, native, type_id, life, alpha, glow, perk, positions):
    return probe.run(
        program,
        native,
        type_id,
        life,
        alpha,
        glow,
        beam_stubs=True,
        native_creature_search=True,
        creature_rows=creatures(positions),
        perk_count=perk,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / probe.FUNCTION)
    source = (config.directory / config.source).read_text()
    assert source.count("arc * effect_scale * 10.0f") == 4
    previous_source = source.replace("arc * effect_scale * 10.0f", "side * 10.0f").replace(
        "                    projectile_render_vec2_t strip0 =",
        "                    projectile_render_vec2_t side = arc * effect_scale;\n                    projectile_render_vec2_t strip0 =",
    )
    assert probe.sha(previous_source.encode()) == "6c41659dc52bbbd401e5f09b0d88390f00a2d83262cd89ad345555b6a520d1a5"
    current = probe.Program(config)
    previous_dir = out / "previous"
    previous_dir.mkdir(exist_ok=True)
    (previous_dir / config.source).write_text(previous_source)
    previous = probe.Program(replace(config, directory=previous_dir))
    wrong_dir = out / "wrong-width"
    wrong_dir.mkdir(exist_ok=True)
    (wrong_dir / config.source).write_text(source.replace("arc * effect_scale * 10.0f", "arc * effect_scale * 9.0f"))
    wrong_width = probe.Program(replace(config, directory=wrong_dir))

    md = probe.capstone.Cs(probe.capstone.CS_ARCH_X86, probe.capstone.CS_MODE_32)
    window = list(md.disasm(current.image.function_bytes(0x424C45, 0x424C9A), 0x424C45))
    x87 = [(i.mnemonic, i.op_str) for i in window if i.mnemonic.startswith("f")]
    assert x87 == [
        ("fld", "dword ptr [esp + 0x54]"),
        ("fmul", "dword ptr [esp + 0x24]"),
        ("fld", "st(0)"),
        ("fld", "dword ptr [esp + 0x24]"),
        ("fmul", "dword ptr [esp + 0x64]"),
        ("fst", "dword ptr [esp + 0x64]"),
        ("fstp", "dword ptr [esp + 0xb8]"),
        ("fmul", "dword ptr [0x46f260]"),
        ("fld", "dword ptr [esp + 0xb8]"),
        ("fmul", "dword ptr [0x46f260]"),
        ("fstp", "dword ptr [esp + 0xc8]"),
        ("fld", "dword ptr [esp + 0xbc]"),
        ("fsub", "st(1)"),
        ("fstp", "dword ptr [esp + 0x44]"),
        ("fstp", "st(0)"),
    ]
    assert current.image.function_bytes(0x46F260, 0x46F264) == struct.pack("<f", 10.0)
    _, find_start, find_end = match.resolve_function(
        match.load_function_manifest(scope="all"),
        "creature_find_in_radius",
    )
    find_sha = probe.sha(current.image.function_bytes(find_start, find_end))
    rows = []
    example = None
    perk_membership = {}
    for position_index, positions in enumerate(POSITIONS):
        for type_id, scale in SCALES.items():
            for life in (0.4, 0.2, 1.2, -0.1):
                for perk in (0, 1):
                    for glow in (0, 1):
                        for alpha in (0.2, 0.7):
                            native = execute(current, True, type_id, life, alpha, glow, perk, positions)
                            candidate = execute(current, False, type_id, life, alpha, glow, perk, positions)
                            assert native["calls"] == candidate["calls"], (
                                position_index,
                                type_id,
                                life,
                                perk,
                                glow,
                                alpha,
                            )
                            assert native["state_sha256"] == candidate["state_sha256"]
                            assert native["creature_state_sha256"] == candidate["creature_state_sha256"]
                            assert native["search_results"] == candidate["search_results"]
                            assert native["native_search_sha256"] == candidate["native_search_sha256"] == find_sha
                            selected = []
                            if type_id != 45 and life != 0.4:
                                # These fixtures stay away from radius/lifecycle equality boundaries.
                                radius = probe.f32(probe.f32(scale) * probe.f32(1.2 if perk else 1.0) * 40.0)
                                for index, x, y, active, stage, size in creatures(positions):
                                    if (
                                        index
                                        and active
                                        and stage > 5
                                        and math.hypot(probe.f32(x) - 111.25, probe.f32(y) - 208.5) - radius
                                        < size * probe.f32(0.14285715) + 3
                                    ):
                                        selected.append(index)
                                assert native["search_results"] == [*selected, 0xFFFFFFFF]
                                assert native["search_instructions_exercised"] > 0
                            else:
                                assert native["search_results"] == []
                            assert sum(name == "grim_draw_quad_points" for name, _ in native["calls"]) == 2 * len(
                                selected,
                            )
                            if position_index == 0 and type_id == 22 and life == 0.2 and glow == 0 and alpha == 0.7:
                                perk_membership[perk] = selected
                            if (
                                position_index == 0
                                and type_id == 23
                                and life == 0.2
                                and perk == 0
                                and glow == 0
                                and alpha == 0.7
                            ):
                                example = native
                            rows.append(
                                {
                                    "positions": position_index,
                                    "type_id": type_id,
                                    "life": life,
                                    "perk": perk,
                                    "glow": glow,
                                    "alpha": alpha,
                                    "calls": len(native["calls"]),
                                    "selected_creatures": selected,
                                    "call_trace_sha256": probe.sha(json.dumps(native["calls"]).encode()),
                                    "projectile_state_sha256": native["state_sha256"],
                                    "creature_state_sha256": native["creature_state_sha256"],
                                    "native_instructions_exercised": native["coverage"],
                                    "candidate_instructions_exercised": candidate["coverage"],
                                    "search_instructions_exercised": native["search_instructions_exercised"],
                                },
                            )
    assert 6 not in perk_membership[0] and 6 in perk_membership[1]
    old = execute(previous, False, 23, 0.2, 0.7, 0, 0, POSITIONS[0])
    native_quads = [args for name, args in example["calls"] if name == "grim_draw_quad_points"]
    old_quads = [args for name, args in old["calls"] if name == "grim_draw_quad_points"]
    # Exact arithmetic for this fixture fits in binary64 before final float32 rounding.
    arc_x = probe.f32(28.5 / math.hypot(14.25, 28.5))
    exact_product = probe.bits(124.375 - arc_x * 3.5 * 10.0)
    rounded_product = probe.bits(124.375 - probe.f32(arc_x * 3.5) * 10.0)
    assert native_quads[0][0] == exact_product == 0x42BA23DD
    assert old_quads[0][0] == rounded_product == 0x42BA23DE
    negatives = []
    for label, program in (("previous-shared-side", previous), ("wrong-width", wrong_width)):
        for life in (0.2, 1.2, -0.1):
            native = execute(current, True, 23, life, 0.7, 0, 0, POSITIONS[0])
            wrong = execute(program, False, 23, life, 0.7, 0, 0, POSITIONS[0])
            differences = [i for i, (a, b) in enumerate(zip(native["calls"], wrong["calls"], strict=True)) if a != b]
            assert differences and all(native["calls"][i][0] == "grim_draw_quad_points" for i in differences)
            negatives.append(
                {
                    "source": label,
                    "life": life,
                    "differing_calls": differences,
                    "native_first_quad": native["calls"][differences[0]],
                    "wrong_first_quad": wrong["calls"][differences[0]],
                },
            )
    r, before = current.result, previous.result
    assert not r.exact and not r.body_byte_exact
    assert r.ratio > before.ratio
    assert r.masked_operand_audit.problem_count == 11 < before.masked_operand_audit.problem_count == 14
    record = {
        "schema_version": 1,
        "kind": "native-ion-chain-product-lifetime",
        "new_source_matches": 0,
        "source_sha256": probe.sha(source.encode()),
        "previous_source_sha256": probe.sha(previous_source.encode()),
        "verifier_sha256": probe.sha(Path(__file__).read_bytes()),
        "engine_sha256": probe.sha(ENGINE.read_bytes()),
        "unicorn_version": probe.unicorn.__version__,
        "image_sha256": probe.sha(match.default_image_path().read_bytes()),
        "native_body_sha256": probe.sha(current.image.function_bytes(current.native_start, current.native_end)),
        "candidate_object_sha256": probe.sha(current.object_path.read_bytes()),
        "candidate_body_sha256": probe.sha(current.body.data),
        "previous_body_sha256": probe.sha(previous.body.data),
        "build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "relocations": current.relocations,
        "native_search": {"start": hex(find_start), "end": hex(find_end), "body_sha256": find_sha},
        "native_x87_window": [
            {"address": hex(i.address), "bytes": bytes(i.bytes).hex(), "instruction": f"{i.mnemonic} {i.op_str}"}
            for i in window
        ],
        "rounding_oracle": {"native_bits": hex(exact_product), "previous_bits": hex(rounded_product)},
        "positions": POSITIONS,
        "creature_fixtures": [creatures(p) for p in POSITIONS],
        "fixtures": rows,
        "negative_controls": negatives,
        "example_native_trace": example,
        "metrics": {
            name: {
                "ratio": v.ratio,
                "instructions": len(v.candidate_lines),
                "references_ok": v.masked_operand_audit.ok_count,
                "reference_problems": v.masked_operand_audit.problem_count,
                "exact": v.exact,
                "body_byte_exact": v.body_byte_exact,
            }
            for name, v in (("previous", before), ("current", r))
        },
        "reference_debt": {
            name: [asdict(e) for e in v.masked_operand_audit.entries if e.status != "ok"]
            for name, v in (("previous", before), ("current", r))
        },
        "boundaries": {
            "Grim": "recording thiscall stubs",
            "normalize": "shared deterministic binary64 sqrt/divide model with float32 output; external DLL not executed",
            "search": "native creature_find_in_radius code executed",
            "perk": "recording 0/1 result stub",
            "texture": "recording no-op",
            "other_math": "machine x87 and native crt_ftol, x87 control word 0x037f",
            "state": "one primary, no players/secondary; seven specified creature records; fixed camera/angle/speed; no non-stack writes",
        },
    }
    (out / "results.json").write_text(json.dumps(record, indent=2, default=str) + "\n")
    print(
        f"{len(rows)} native-search chain fixtures agree; {len(negatives)} compiled defects rejected; one-bit rounding oracle verified.",
    )


if __name__ == "__main__":
    main()
