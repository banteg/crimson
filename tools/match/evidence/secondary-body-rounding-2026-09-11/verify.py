"""Verify rocket body rounding against native machine code and independent float oracles."""

import argparse
import importlib.util
import itertools
import json
import random
import struct
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE = HERE.parent / "plasma-head-alpha-2026-09-10/verify.py"
SPEC = importlib.util.spec_from_file_location("secondary_probe", ENGINE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
match = probe.match
BEFORE_SHA = "3b5c5cb097ebcf0cf298758ccefbf370202dcc41068f5808e99c9db503afb986"
BODY = {1: 14.0, 2: 10.0, 4: 8.0}
FLAME = {1: 60.0, 2: 40.0, 4: 30.0}
# (pool slot, type, angle, x, y, active); each X distinguishes the two store boundaries.
ROUNDING_CASES = (
    (1, 1, 0.3, 7.486588478088379, 39.011714935302734, 1),
    (7, 2, 0.3, -1.3973995447158813, 16.589393615722656, 1),
    (4, 4, 0.3, 4.606505393981934, 37.675537109375, 1),
)


def execute(program, native, rows, alpha, glow):
    return probe.run(program, native, None, 0.4, alpha, glow, secondary_rows=rows)


def same_trace(native, candidate):
    assert native["calls"] == candidate["calls"]
    for key in ("state_sha256", "secondary_state_sha256", "player_state_sha256", "creature_state_sha256"):
        assert native[key] == candidate[key], key


def oracle(trace, rows, glow):
    active = sorted((row for row in rows if row[5]), key=lambda row: row[0])
    bodies = [row for row in active if row[1] in BODY]
    expected_sizes = ([140.0] * len(active) if glow else []) + [BODY[row[1]] for row in bodies]
    expected_sizes += [FLAME[row[1]] for row in bodies] if glow else []
    quads = [args for name, args in trace["calls"] if name == "grim_draw_quad"]
    assert [args[2:] for args in quads] == [[probe.bits(size)] * 2 for size in expected_sizes]
    assert not any(name == "grim_draw_quad_points" for name, _ in trace["calls"])
    body_quads = [args for args in quads if args[2] in {probe.bits(size) for size in BODY.values()}]
    records = []
    for row, args in zip(bodies, body_quads, strict=True):
        index, kind, _angle, x, y, _active = row
        half = BODY[kind] / 2.0
        # Binary32 fixture values with these finite magnitudes sum exactly in binary64.
        # Native X remains extended through subtraction; Y is explicitly stored first.
        x = probe.f32(x)
        y = probe.f32(y)
        expected_x = probe.bits(13.125 + x - half)
        expected_y = probe.bits(probe.f32(-21.75 + y) - half)
        prematurely_rounded_x = probe.bits(probe.f32(13.125 + x) - half)
        assert args[:2] == [expected_x, expected_y], (row, args, expected_x, expected_y)
        records.append({
            "index": index, "type": kind, "x": hex(expected_x), "y": hex(expected_y),
            "early_x_store": hex(prematurely_rounded_x),
        })
    return records


def native_windows(program):
    md = probe.capstone.Cs(probe.capstone.CS_ARCH_X86, probe.capstone.CS_MODE_32)
    windows = (
        (1, 0x42588C, 0x4258DD, 0x46F278, "esp + 0xc4", "esp + 0x3c", "esp + 0xc8", "esp + 0x40"),
        (2, 0x425906, 0x42595D, 0x46F288, "esp + 0xd4", "esp + 0x94", "esp + 0xd8", "esp + 0x98"),
        (4, 0x42598F, 0x4259E6, 0x46F25C, "esp + 0xdc", "esp + 0x8c", "esp + 0xe0", "esp + 0x90"),
    )
    records = []
    for kind, start, end, constant, y_sum, x_out, y_sum_after_push, y_out in windows:
        code = program.image.function_bytes(start, end)
        instructions = list(md.disasm(code, start))
        assert instructions[-1].mnemonic == "call"
        assert instructions[-1].op_str.endswith("+ 0x114]")
        assert all(ins.mnemonic != "call" for ins in instructions[:-1])
        x87 = [(ins.mnemonic, ins.op_str) for ins in instructions if ins.mnemonic.startswith("f")]
        assert x87 == [
            ("fld", f"dword ptr [{hex(program.address('camera_offset_x'))}]"),
            ("fadd", "dword ptr [esi - 4]"),
            ("fld", f"dword ptr [{hex(program.address('camera_offset_y'))}]"),
            ("fadd", "dword ptr [esi]"),
            ("fstp", f"dword ptr [{y_sum}]"),
            ("fsub", f"dword ptr [{hex(constant)}]"),
            ("fstp", f"dword ptr [{x_out}]"),
            ("fld", f"dword ptr [{y_sum_after_push}]"),
            ("fsub", f"dword ptr [{hex(constant)}]"),
            ("fstp", f"dword ptr [{y_out}]"),
        ]
        assert program.image.function_bytes(constant, constant + 4) == struct.pack("<f", BODY[kind] / 2)
        records.append({"type": kind, "start": hex(start), "end": hex(end), "sha256": probe.sha(code), "x87": x87})
    return records


def reverted(source, kinds):
    for kind in kinds:
        half = int(BODY[kind] / 2)
        old = f"""            draw_pos -= {half}.0f;
            grim_interface_ptr->grim_set_color(
                0.8f, 0.8f, 0.8f, transition_alpha * 0.9f);"""
        new = f"""            grim_interface_ptr->grim_set_color(
                0.8f, 0.8f, 0.8f, transition_alpha * 0.9f);
            draw_pos -= {half}.0f;"""
        assert source.count(old) == 1
        source = source.replace(old, new)
    return source


def layout_check(config, out):
    directory = out / "layout"
    directory.mkdir(exist_ok=True)
    source = '''#include "crimsonland_gameplay.h"
#include <stddef.h>
typedef char check_size[sizeof(secondary_projectile_t) == 0x2c ? 1 : -1];
typedef char check_active[offsetof(secondary_projectile_t, active) == 0 ? 1 : -1];
typedef char check_angle[offsetof(secondary_projectile_t, angle) == 4 ? 1 : -1];
typedef char check_x[offsetof(secondary_projectile_t, pos_x) == 12 ? 1 : -1];
typedef char check_y[offsetof(secondary_projectile_t, pos) == 16 ? 1 : -1];
typedef char check_type[offsetof(secondary_projectile_t, fields.type_id) == 28 ? 1 : -1];
typedef char check_pool[sizeof(secondary_projectile_pool_t) == 0x2c * 64 ? 1 : -1];
typedef char check_ids[SECONDARY_PROJECTILE_TYPE_ROCKET == 1
    && SECONDARY_PROJECTILE_TYPE_SEEKER_ROCKET == 2
    && SECONDARY_PROJECTILE_TYPE_EXPLODING == 3
    && SECONDARY_PROJECTILE_TYPE_ROCKET_MINIGUN == 4 ? 1 : -1];
extern "C" void secondary_layout_check(void) {}
'''
    (directory / config.source).write_text(source)
    obj = match.compile_scratch(replace(config, directory=directory, symbol="secondary_layout_check"), force=True)
    return {"source_sha256": probe.sha(source.encode()), "object_sha256": probe.sha(obj.read_bytes())}


def metrics(result):
    return {
        "ratio": result.ratio, "target_instructions": len(result.target_lines),
        "candidate_instructions": len(result.candidate_lines), "prefix": result.prefix_instructions,
        "references_ok": result.masked_operand_audit.ok_count,
        "references_unresolved": result.masked_operand_audit.unresolved_count,
        "references_mismatched": result.masked_operand_audit.mismatch_count,
        "exact": result.exact, "body_byte_exact": result.body_byte_exact,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert probe.unicorn.__version__ == "2.1.4"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
    source = (config.directory / config.source).read_text()
    before = (HERE / "before.cpp").read_text()
    assert probe.sha(before.encode()) == BEFORE_SHA
    assert reverted(source, BODY) == before
    current = probe.Program(config)
    layout = layout_check(config, out)
    windows = native_windows(current)
    programs = {}
    for kind in BODY:
        directory = out / f"revert-{kind}"
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_text(reverted(source, (kind,)))
        programs[kind] = probe.Program(replace(config, directory=directory))
    previous_dir = out / "previous"
    previous_dir.mkdir(exist_ok=True)
    (previous_dir / config.source).write_text(before)
    previous = probe.Program(replace(config, directory=previous_dir))
    fixture_rows = []
    geometries = ((111.25, 208.5), (-0.4427504241466522, 1822.830322265625), (242.88197326660156, -800.8319702148438))
    for index, kind, active, glow, alpha, position in itertools.product(
        (0, 1, 31, 63), range(6), (0, 1), (0, 1), (0.0, 0.7, 1.5), geometries,
    ):
        fixture_rows.append((((index, kind, 0.3, *position, active),), alpha, glow))
    fixture_rows.extend((((), alpha, glow) for alpha, glow in itertools.product((0.0, 0.7, 1.5), (0, 1))))
    fixture_rows.extend((((row,), alpha, glow) for row, alpha, glow in itertools.product(ROUNDING_CASES, (0.2, 0.7, 1.5), (0, 1))))
    mixed = (
        (0, 1, 0.3, 7.486588478088379, 39.011714935302734, 1),
        (7, 2, -2.4, -1.3973995447158813, 16.589393615722656, 1),
        (31, 3, 1.5, 100.0, -200.0, 1),
        (62, 4, 0.0, 250.0, 99.0, 0),
        (63, 4, 4.0, 4.606505393981934, 37.675537109375, 1),
    )
    fixture_rows.extend(((mixed, alpha, glow) for alpha, glow in itertools.product((0.0, 0.7, 1.5), (0, 1))))
    rng = random.Random(0x425700)
    for index in range(300):
        row = (index % 64, (1, 2, 4)[index % 3], probe.f32(rng.uniform(-15, 15)),
               probe.f32(rng.uniform(-2048, 2048)), probe.f32(rng.uniform(-2048, 2048)), 1)
        fixture_rows.append(((row,), 0.7, 1))
    results = []
    for index, (rows, alpha, glow) in enumerate(fixture_rows):
        native = execute(current, True, rows, alpha, glow)
        candidate = execute(current, False, rows, alpha, glow)
        same_trace(native, candidate)
        oracle_rows = oracle(native, rows, glow)
        results.append({
            "rows": rows, "alpha": alpha, "glow": glow,
            "call_trace_sha256": probe.sha(json.dumps(native["calls"]).encode()),
            "secondary_state_sha256": native["secondary_state_sha256"],
            "native_instructions_exercised": native["coverage"],
            "candidate_instructions_exercised": candidate["coverage"],
            "body_oracle": oracle_rows,
        })
        if (index + 1) % 200 == 0:
            print(f"Verified {index + 1} secondary fixtures", flush=True)
    negatives = []
    for row in ROUNDING_CASES:
        kind = row[1]
        native = execute(current, True, (row,), 0.7, 1)
        oracle_row = oracle(native, (row,), 1)[0]
        assert oracle_row["x"] != oracle_row["early_x_store"]
        for name, program in ((f"revert-{kind}", programs[kind]), ("previous", previous)):
            wrong = execute(program, False, (row,), 0.7, 1)
            differences = [i for i, (a, b) in enumerate(zip(native["calls"], wrong["calls"], strict=True)) if a != b]
            assert len(differences) == 1
            i = differences[0]
            assert native["calls"][i][0] == wrong["calls"][i][0] == "grim_draw_quad"
            assert native["calls"][i][1][1:] == wrong["calls"][i][1][1:]
            assert hex(wrong["calls"][i][1][0]) == oracle_row["early_x_store"]
            negatives.append({
                "control": name, "row": row, "native_return_site": hex(native["return_sites"][i]),
                "native": native["calls"][i], "candidate": wrong["calls"][i], "oracle": oracle_row,
            })
    record = {
        "schema_version": 1, "kind": "secondary-rocket-body-x87-rounding", "new_source_matches": 0,
        "source_sha256": probe.sha(source.encode()), "before_source_sha256": BEFORE_SHA,
        "verifier_sha256": probe.sha(Path(__file__).read_bytes()), "engine_sha256": probe.sha(ENGINE.read_bytes()),
        "unicorn_version": probe.unicorn.__version__, "image_sha256": probe.sha(match.DEFAULT_IMAGE_PATH.read_bytes()),
        "native_body_sha256": probe.sha(current.image.function_bytes(current.native_start, current.native_end)),
        "candidate_object_sha256": probe.sha(current.object_path.read_bytes()),
        "candidate_body_sha256": probe.sha(current.body.data), "relocations": current.relocations,
        "build_key": match._scratch_build_key(config, match.DEFAULT_MATCH_ROOT),
        "layout": layout, "native_windows": windows, "fixtures": results, "negative_controls": negatives,
        "control_sources": {str(kind): probe.sha((p.config.directory / config.source).read_bytes()) for kind, p in programs.items()},
        "metrics": {"previous": metrics(previous.result), "current": metrics(current.result)},
        "boundaries": {
            "calls": "recording Grim thiscall stubs and effect/perk stubs; complete ordered argument bits",
            "math": "native x87 and crt_ftol under control word 0x037f; finite binary32 fixture inputs",
            "state": "zero players and primary projectiles; secondary slots initialized from checked layout; no non-stack writes",
            "scope": "caller behavior on these fixtures; not GPU output, all-input equivalence, or whole-function matching",
        },
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"Verified {len(results)} secondary fixtures and {len(negatives)} rejected controls", flush=True)


if __name__ == "__main__":
    main()
