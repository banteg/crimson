"""Check laser trig stores using native execution and a PC24 arithmetic oracle."""

import argparse
import collections
import itertools
import json
import math
import random
import re
from dataclasses import replace
from pathlib import Path

import execute

HERE = Path(__file__).resolve().parent
BEFORE_SHA = "609e75e367fff344342547b6227072827986038c6fd93e1db6636dd7dd874bb0"
f32, bits, sha = execute.f32, execute.bits, execute.sha


def player(index, position, heading, health=100.0, perk=1):
    return {
        "index": index,
        "position": list(position),
        "heading": f32(heading),
        "health": f32(health),
        "sharpshooter": perk,
    }


def fixtures():
    rng = random.Random(0x422D02)
    for index in range(2048):
        position = [f32(rng.uniform(-2048, 2048)) for _ in range(2)]
        heading = f32(rng.uniform(-10, 10))
        camera = [f32(rng.uniform(-1024, 1024)) for _ in range(2)]
        for cw in (0x007F, 0x037F):
            yield {
                "group": "discovery" if index < 512 else "extension",
                "players": [player(0, position, heading)],
                "player_count": 1,
                "camera": camera,
                "alpha": f32(0.7),
                "glow": 0,
                "fpcw": cw,
            }
    for count, perks, health, alpha, glow, cw in itertools.product(
        (0, 1, 2),
        ((0, 0), (1, 0), (0, 1), (1, 1)),
        ((100.0, 100.0), (0.0, 100.0), (100.0, -1.0)),
        (0.0, 0.001, 0.2, 0.7, 1.0, 1.5),
        (0, 1),
        (0x007F, 0x037F),
    ):
        yield {
            "group": "gates-and-alpha",
            "players": [
                player(0, (100.0, 150.0), 0.3, health[0], perks[0]),
                player(1, (220.0, 210.0), 0.7, health[1], perks[1]),
            ],
            "player_count": count,
            "camera": [13.125, -21.75],
            "alpha": f32(alpha),
            "glow": glow,
            "fpcw": cw,
        }
    headings = (-10.0, -6.2831853, -3.1415927, -1.5707964, -0.0, 0.0, 1.5707964, 3.1415927, 6.2831853, 10.0)
    for heading, position, camera, cw in itertools.product(
        headings,
        ((0.0, 0.0), (15.0, -15.0)),
        ((0.0, 0.0), (-15.0, 15.0)),
        (0x007F, 0x037F),
    ):
        yield {
            "group": "axes-and-cancellation",
            "players": [player(0, position, heading)],
            "player_count": 1,
            "camera": list(camera),
            "alpha": f32(0.7),
            "glow": 0,
            "fpcw": cw,
        }


def corners(row, camera):
    """Independent PC24 model: FCOS/FSIN stay wide until the native operation/store."""
    x, y = row["position"]
    aim = row["heading"]
    heading = f32(aim - f32(1.5707964))
    end_x = f32(x + f32(math.cos(heading) * 512.0))
    # The far-end sine is explicitly stored before multiplication (0x422d87).
    end_y = f32(y + f32(f32(math.sin(heading)) * 512.0))
    start_heading = f32(heading - f32(0.150915))
    start_x = f32(x + f32(math.cos(start_heading) * 15.0))
    start_y = f32(y + f32(math.sin(start_heading) * 15.0))
    width_x = f32(math.cos(aim) * f32(1.1))
    width_y = f32(math.sin(aim) * f32(1.1))
    start_x, start_y = f32(start_x + camera[0]), f32(start_y + camera[1])
    end_x, end_y = f32(end_x + camera[0]), f32(end_y + camera[1])
    return [
        bits(value)
        for value in (
            start_x - width_x,
            start_y - width_y,
            start_x + width_x,
            start_y + width_y,
            end_x + width_x,
            end_y + width_y,
            end_x - width_x,
            end_y - width_y,
        )
    ]


def layout_check(config, out):
    source = """#include "crimsonland_gameplay.h"
#include <stddef.h>
typedef char size_check[sizeof(player_state_t) == 0x360 ? 1 : -1];
typedef char table_check[sizeof(player_state_table) == 0x360 * 2 ? 1 : -1];
typedef char position_check[offsetof(player_state_t, position) == 0x14 ? 1 : -1];
typedef char health_check[offsetof(player_state_t, health) == 0x24 ? 1 : -1];
typedef char heading_check[offsetof(player_state_t, aim_heading) == 0x300 ? 1 : -1];
typedef char perks_check[offsetof(player_state_t, perk_counts) == 0xb8 ? 1 : -1];
extern "C" void laser_layout_check(void) {}
"""
    directory = out / "layout"
    directory.mkdir(exist_ok=True)
    (directory / config.source).write_text(source)
    obj = execute.match.compile_scratch(replace(config, directory=directory, symbol="laser_layout_check"), force=True)
    header = (execute.match.REPO_ROOT / "tools/match/include/grim2d_cpp.h").read_text()
    methods = re.findall(r"virtual\s+[^;{}]*?\b(grim_\w+)\s*\((.*?)\)", header, re.DOTALL)
    assert all(methods[slot // 4][0] == name for slot, (name, _) in execute.probe.SLOTS.items())
    return {
        "source_sha256": sha(source.encode()),
        "object_sha256": sha(obj.read_bytes()),
        "grim_header_sha256": sha(header.encode()),
    }


def metrics(program):
    result = program.result
    md = execute.probe.capstone.Cs(execute.probe.capstone.CS_ARCH_X86, execute.probe.capstone.CS_MODE_32)
    first = next(md.disasm(program.body.data, 0))
    assert first.mnemonic == "sub" and first.op_str.startswith("esp, ")
    return {
        "ratio": result.ratio,
        "instructions": len(result.candidate_lines),
        "native_instructions": len(result.target_lines),
        "frame": int(first.op_str.split(", ")[1], 0),
        "references_ok": result.masked_operand_audit.ok_count,
        "references_unresolved": result.masked_operand_audit.unresolved_count,
        "references_mismatched": result.masked_operand_audit.mismatch_count,
        "prefix": result.prefix_instructions,
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
    }


def native_windows(program):
    md = execute.probe.capstone.Cs(execute.probe.capstone.CS_ARCH_X86, execute.probe.capstone.CS_MODE_32)
    ins = {
        i.address: i
        for i in md.disasm(program.image.function_bytes(program.native_start, program.native_end), program.native_start)
    }
    expected = {
        0x422D85: ("fsin", ""),
        0x422D87: ("fstp", "dword ptr [esp + 0x30]"),
        0x422DCB: ("fcos", ""),
        0x422DCD: ("fmul", "dword ptr [0x46f360]"),
        0x422DD3: ("fstp", "dword ptr [esp + 0x7c]"),
        0x422DD7: ("fsin", ""),
        0x422DD9: ("fmul", "dword ptr [0x46f360]"),
        0x422DF1: ("fstp", "dword ptr [esp + 0x48]"),
        0x422DF9: ("fcos", ""),
        0x422DFB: ("fmul", "dword ptr [0x46f560]"),
        0x422E03: ("fsin", ""),
        0x422E05: ("fmul", "dword ptr [0x46f560]"),
        0x422E0B: ("fstp", "dword ptr [esp + 0xb0]"),
    }
    for address, operation in expected.items():
        assert (ins[address].mnemonic, ins[address].op_str) == operation
    return [
        {"address": hex(a), "bytes": bytes(ins[a].bytes).hex(), "instruction": " ".join(op).rstrip()}
        for a, op in expected.items()
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert execute.unicorn.__version__ == "2.1.4"
    config = execute.match.load_scratch_config(execute.match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
    if args.source:
        directory = out / "candidate"
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_bytes(args.source.read_bytes())
        config = replace(config, directory=directory)
    program = execute.Program(config)
    before = (HERE / "before.cpp").read_bytes()
    assert sha(before) == BEFORE_SHA
    directory = out / "before"
    directory.mkdir(exist_ok=True)
    (directory / config.source).write_bytes(before)
    previous = execute.Program(replace(config, directory=directory))
    layout = layout_check(config, out)
    operations = native_windows(program)
    groups = collections.Counter()
    failures = []
    oracle_count = 0
    coverage = set()
    fixture_path = out / "fixtures.jsonl"
    with fixture_path.open("w") as stream:
        for index, case in enumerate(fixtures()):
            native = execute.run(program, True, case)
            candidate = execute.run(program, False, case)
            assert native["calls"] == candidate["calls"], (index, case, native["calls"], candidate["calls"])
            assert native["pools"] == candidate["pools"]
            points = [args for name, args in native["calls"] if name == "grim_draw_quad_points"]
            active = [row for row in case["players"] if row["index"] < case["player_count"] and row["health"] > 0]
            if case["players"][0]["sharpshooter"] <= 0:
                active = []
            assert len(points) == len(active), (index, case)
            if case["fpcw"] == 0x007F:
                assert points == [corners(row, case["camera"]) for row in active], (index, case)
                oracle_count += 1
            wrong = execute.run(previous, False, case)
            assert wrong["pools"] == native["pools"]
            if wrong["calls"] != native["calls"]:
                differences = [
                    [i, a, b] for i, (a, b) in enumerate(zip(native["calls"], wrong["calls"], strict=True)) if a != b
                ]
                assert all(a[0] == b[0] == "grim_draw_quad_points" for _, a, b in differences)
                failures.append({"index": index, "fpcw": case["fpcw"], "differences": differences})
            groups[case["group"]] += 1
            coverage.update(native["coverage_offsets"])
            stream.write(
                json.dumps(
                    {
                        "index": index,
                        "case": case,
                        "native_corners": points,
                        "native_colors": native["calls"][1:4],
                        "native_trace_sha256": sha(json.dumps(native["calls"]).encode()),
                        "pools": native["pools"],
                        "before_agrees": wrong["calls"] == native["calls"],
                    },
                    separators=(",", ":"),
                )
                + "\n",
            )
    assert failures and not program.result.exact and not program.result.body_byte_exact
    record = {
        "schema_version": 1,
        "kind": "native-laser-trig-rounding",
        "new_source_matches": 0,
        "source_sha256": sha((config.directory / config.source).read_bytes()),
        "before_source_sha256": BEFORE_SHA,
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "executor_sha256": sha((HERE / "execute.py").read_bytes()),
        "program_loader_sha256": sha(execute.ENGINE.read_bytes()),
        "image_sha256": sha(execute.match.default_image_path().read_bytes()),
        "native_body_sha256": sha(program.image.function_bytes(program.native_start, program.native_end)),
        "candidate_body_sha256": sha(program.body.data),
        "candidate_object_sha256": sha(program.object_path.read_bytes()),
        "before_body_sha256": sha(previous.body.data),
        "unicorn_version": execute.unicorn.__version__,
        "layout": layout,
        "native_operations": operations,
        "fixtures": {
            "file": fixture_path.name,
            "sha256": sha(fixture_path.read_bytes()),
            "count": sum(groups.values()),
            "groups": groups,
        },
        "pc24_oracle_cases": oracle_count,
        "before_failures": failures,
        "native_coverage_offsets": sorted(coverage),
        "metrics": {"before": metrics(previous), "current": metrics(program)},
        "boundaries": {
            "execution": "Native and relocated VC6 object; zero primary/secondary/creature pools; zero to two players; no non-stack writes",
            "external": "Recording Grim/effect/perk contracts clobber volatile registers; native crt_ftol; no unmodeled execution",
            "arithmetic": "PC24 and PC64 x87 round-to-nearest; finite ordinary inputs; independent PC24 libm-trig/float-store oracle",
            "scope": "Caller argument identity for recorded cases; no whole-function exactness, GPU pixel proof, or out-of-range trig claim",
        },
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(
        f"{sum(groups.values())} native cases agree; {oracle_count} PC24 oracle cases; {len(failures)} old-source failures.",
    )


if __name__ == "__main__":
    main()
