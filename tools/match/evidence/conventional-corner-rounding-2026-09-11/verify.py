"""Verify conventional corners against native x87, with a rational oracle and rejected source."""

import argparse
import collections
import json
import re
import struct
from dataclasses import replace
from pathlib import Path

import execute
import fixtures

HERE = Path(__file__).resolve().parent
BEFORE_SHA = "fb86981bab2b7365e5374a0cbf8f71d7b46b8e01d259e4fceec0c510217976cd"


def metrics(program):
    result = program.result
    md = execute.probe.capstone.Cs(execute.probe.capstone.CS_ARCH_X86, execute.probe.capstone.CS_MODE_32)
    prologue = next(md.disasm(program.body.data, 0))
    assert prologue.mnemonic == "sub" and prologue.op_str.startswith("esp, ")
    return {
        "ratio": result.ratio,
        "instructions": len(result.candidate_lines),
        "native_instructions": len(result.target_lines),
        "frame": int(prologue.op_str.split(", ")[1], 0),
        "references_ok": result.masked_operand_audit.ok_count,
        "references_unresolved": result.masked_operand_audit.unresolved_count,
        "references_mismatched": result.masked_operand_audit.mismatch_count,
        "prefix": result.prefix_instructions,
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
    }


def layout_check(config, out):
    source = """#include "crimsonland_gameplay.h"
#include <stddef.h>
typedef char size_check[sizeof(projectile_t) == 0x40 ? 1 : -1];
typedef char pool_check[sizeof(projectile_pool_t) == 0x40 * 96 ? 1 : -1];
typedef char active_check[offsetof(projectile_t, active) == 0 ? 1 : -1];
typedef char angle_check[offsetof(projectile_t, angle) == 4 ? 1 : -1];
typedef char position_check[offsetof(projectile_t, position) == 8 ? 1 : -1];
typedef char origin_check[offsetof(projectile_t, fields.origin) == 16 ? 1 : -1];
typedef char velocity_check[offsetof(projectile_t, fields.velocity) == 24 ? 1 : -1];
typedef char type_check[offsetof(projectile_t, fields.type_id) == 32 ? 1 : -1];
typedef char life_check[offsetof(projectile_t, fields.life_timer) == 36 ? 1 : -1];
typedef char scale_check[offsetof(projectile_t, fields.speed_scale) == 44 ? 1 : -1];
typedef char ids_check[PROJECTILE_TYPE_NONE == 0 && PROJECTILE_TYPE_PISTOL == 1
    && PROJECTILE_TYPE_ASSAULT_RIFLE == 2 && PROJECTILE_TYPE_GAUSS_GUN == 6
    && PROJECTILE_TYPE_SPLITTER_GUN == 29 ? 1 : -1];
extern "C" void conventional_layout_check(void) {}
"""
    directory = out / "layout"
    directory.mkdir(exist_ok=True)
    (directory / config.source).write_text(source)
    obj = execute.match.compile_scratch(
        replace(config, directory=directory, symbol="conventional_layout_check"),
        force=True,
    )
    header = (execute.match.REPO_ROOT / "tools/match/include/grim2d_cpp.h").read_text()
    methods = re.findall(r"virtual\s+[^;{}]*?\b(grim_\w+)\s*\((.*?)\)", header, re.DOTALL)
    assert all(methods[slot // 4][0] == name for slot, (name, _) in execute.probe.SLOTS.items())
    return {
        "source_sha256": execute.sha(source.encode()),
        "object_sha256": execute.sha(obj.read_bytes()),
        "grim_header_sha256": execute.sha(header.encode()),
    }


def native_windows(program):
    md = execute.probe.capstone.Cs(execute.probe.capstone.CS_ARCH_X86, execute.probe.capstone.CS_MODE_32)
    windows = ((2, 0x4230E5, 0x4231EA), (1, 0x4231F3, 0x423345), (6, 0x423395, 0x4234E7), (3, 0x4234E7, 0x42363A))
    expected = {
        0x4230EE: ("fld", "st(0)"),
        0x423168: ("fld", "st(0)"),
        0x4231FC: ("fst", "dword ptr [esp + 0x94]"),
        0x423239: ("fsub", "dword ptr [esp + 0x94]"),
        0x4232B2: ("fst", "dword ptr [esp + 0x34]"),
        0x4232CA: ("fadd", "st(1)"),
        0x4232F5: ("fld", "dword ptr [esp + 0x34]"),
        0x423300: ("fsub", "st(1)"),
        0x42339E: ("fst", "dword ptr [esp + 0xec]"),
        0x4233DB: ("fsub", "dword ptr [esp + 0xec]"),
        0x423460: ("fst", "dword ptr [esp + 0x34]"),
        0x423478: ("fadd", "st(1)"),
        0x42349E: ("fld", "dword ptr [esp + 0x34]"),
        0x4234B5: ("fsub", "st(1)"),
        0x4234F0: ("fst", "dword ptr [esp + 0x24]"),
        0x423527: ("fsub", "dword ptr [esp + 0x24]"),
        0x4235AC: ("fst", "dword ptr [esp + 0x34]"),
        0x4235C4: ("fadd", "st(1)"),
        0x4235EF: ("fld", "dword ptr [esp + 0x34]"),
        0x4235FA: ("fsub", "st(1)"),
    }
    seen, records = set(), []
    for kind, start, end in windows:
        code = program.image.function_bytes(start, end)
        instructions = list(md.disasm(code, start))
        for ins in instructions:
            if ins.address in expected:
                assert (ins.mnemonic, ins.op_str) == expected[ins.address]
                seen.add(ins.address)
        records.append(
            {
                "type": kind,
                "start": hex(start),
                "end": hex(end),
                "sha256": execute.sha(code),
                "x87": [
                    [hex(ins.address), ins.mnemonic, ins.op_str] for ins in instructions if ins.mnemonic.startswith("f")
                ],
            },
        )
    assert seen == set(expected)
    for address, value in ((0x46F5F4, 1.2), (0x46F560, 1.1), (0x46F334, 0.7)):
        assert program.image.function_bytes(address, address + 4) == struct.pack("<f", value)
    return records


def points(trace):
    return [arguments for name, arguments in trace["calls"] if name == "grim_draw_quad_points"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert execute.unicorn.__version__ == "2.1.4"
    config = execute.match.load_scratch_config(execute.match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
    if args.source is not None:
        directory = out / "source"
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_bytes(args.source.read_bytes())
        config = replace(config, directory=directory)
    before = (HERE / "before.cpp").read_bytes()
    assert execute.sha(before) == BEFORE_SHA
    current = execute.Program(config)
    directory = out / "before"
    directory.mkdir(exist_ok=True)
    (directory / config.source).write_bytes(before)
    previous = execute.Program(replace(config, directory=directory))
    layout = layout_check(config, out)
    windows = native_windows(current)
    groups, negative_groups = collections.Counter(), collections.Counter()
    coverage_native, coverage_candidate = set(), set()
    negative_controls = []
    trace_path = out / "fixtures.jsonl"
    with trace_path.open("w") as stream:
        for index, case in enumerate(fixtures.fixtures()):
            native = execute.run(current, True, case)
            candidate = execute.run(current, False, case)
            assert native["calls"] == candidate["calls"], (index, case, native["calls"], candidate["calls"])
            assert native["pools"] == candidate["pools"] and native["writes"] == candidate["writes"]
            assert native["ftol_sha256"] == candidate["ftol_sha256"]
            active = sorted((row for row in case["records"] if row["active"]), key=lambda row: row["index"])
            oracle = [fixtures.corner_bits(row, case["camera"], case["fpcw"]) for row in active]
            assert points(native) == oracle, (index, case, points(native), oracle)
            if case["group"] == "discovery":
                wrong = execute.run(previous, False, case)
                old_oracle = [
                    fixtures.corner_bits(row, case["camera"], case["fpcw"], previous_source=True) for row in active
                ]
                assert points(wrong) == old_oracle
                assert native["pools"] == wrong["pools"] and native["writes"] == wrong["writes"]
                differences = [
                    i for i, (a, b) in enumerate(zip(native["calls"], wrong["calls"], strict=True)) if a != b
                ]
                if differences:
                    assert len(differences) == 1
                    call = differences[0]
                    assert native["calls"][call][0] == wrong["calls"][call][0] == "grim_draw_quad_points"
                    assert case["fpcw"] == 0x037F
                    kind = active[0]["type_id"]
                    negative_groups[kind] += 1
                    negative_controls.append(
                        {
                            "fixture": index,
                            "type": kind,
                            "call_index": call,
                            "native_return_site": hex(native["return_sites"][call]),
                            "native": points(native)[0],
                            "previous": points(wrong)[0],
                            "differing_coordinates": [
                                j
                                for j, (a, b) in enumerate(zip(points(native)[0], points(wrong)[0], strict=True))
                                if a != b
                            ],
                        },
                    )
            coverage_native.update(native["coverage_offsets"])
            coverage_candidate.update(candidate["coverage_offsets"])
            groups[case["group"]] += 1
            row = {
                "index": index,
                "case": case,
                "corners": oracle,
                "call_trace_sha256": execute.sha(json.dumps(native["calls"]).encode()),
                "pools": native["pools"],
                "writes": native["writes"],
                "native_instructions": len(native["coverage_offsets"]),
                "candidate_instructions": len(candidate["coverage_offsets"]),
            }
            stream.write(json.dumps(row, separators=(",", ":")) + "\n")
            if (index + 1) % 200 == 0:
                print(f"Verified {index + 1} conventional fixtures", flush=True)
    assert groups["discovery"] == 1280 and len(negative_controls) == 61
    assert set(negative_groups) == {1, 3, 6}
    assert 0x42365D - current.native_start in coverage_native
    record = {
        "schema_version": 1,
        "kind": "conventional-projectile-corner-x87-rounding",
        "new_source_matches": 0,
        "source_sha256": execute.sha((config.directory / config.source).read_bytes()),
        "before_source_sha256": BEFORE_SHA,
        "verifier_sha256": execute.sha(Path(__file__).read_bytes()),
        "execution_sha256": execute.sha((HERE / "execute.py").read_bytes()),
        "fixture_generator_sha256": execute.sha((HERE / "fixtures.py").read_bytes()),
        "engine_sha256": execute.sha(execute.ENGINE.read_bytes()),
        "unicorn_version": execute.unicorn.__version__,
        "image_sha256": execute.sha(execute.match.default_image_path().read_bytes()),
        "native_body_sha256": execute.sha(current.image.function_bytes(current.native_start, current.native_end)),
        "candidate_object_sha256": execute.sha(current.object_path.read_bytes()),
        "candidate_body_sha256": execute.sha(current.body.data),
        "build_key": execute.match._scratch_build_key(config, execute.match.DEFAULT_MATCH_ROOT),
        "layout": layout,
        "native_windows": windows,
        "relocations": current.relocations,
        "fixtures": {
            "file": trace_path.name,
            "sha256": execute.sha(trace_path.read_bytes()),
            "count": sum(groups.values()),
            "groups": dict(groups),
        },
        "negative_control_counts": dict(negative_groups),
        "negative_controls": negative_controls,
        "coverage": {"native_offsets": sorted(coverage_native), "candidate_offsets": sorted(coverage_candidate)},
        "metrics": {"previous": metrics(previous), "current": metrics(current)},
        "boundaries": {
            "calls": "complete ordered argument bits; recording Grim calls and effect/perk stubs with volatile-register clobbers",
            "math": "native x87 with control words 0x007f and 0x037f; rational round-to-nearest-even oracle; bounded finite fixtures",
            "state": "checked 96-slot primary layout; unchanged player, creature and secondary pools; only active-byte clears for type zero",
            "abi": "caller stack guard, callee-saved registers, balanced x87 tags and unchanged control word",
            "scope": "these caller traces and pool states; no GPU execution, external-renderer equivalence or whole-function match claim",
        },
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(
        f"Verified {sum(groups.values())} conventional fixtures and {len(negative_controls)} rejected-source cases",
        flush=True,
    )


if __name__ == "__main__":
    main()
