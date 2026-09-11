"""Compare native player_update with the before/current sources at gameplay PC=24."""

import argparse
import hashlib
import json
import struct
from dataclasses import replace
from pathlib import Path

from fixtures import scenarios
from layout import check_layout
from runner import ENGINE, ROOT, e, run

HERE = Path(__file__).resolve().parent
BASELINE_SHA = "61ce66d1d73dd0b7064b89019dd94d20c1b8e4dd1d133e118a630fa833a5a46b"
IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
ENGINE_SHA = "f562a0e40b6024b13bfe12ebb2fd15f39d24b3e61824866d03c0aa872e9ee546"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def observation(result):
    return {key: result[key] for key in ("state", "calls")}


def metrics(program):
    r = program.result
    return {
        "ratio": r.ratio,
        "fuzzy_weighted_bytes": r.ratio * (program.native_end - program.native_start),
        "candidate_instructions": len(r.candidate_lines),
        "target_instructions": len(r.target_lines),
        "prefix": r.prefix_instructions,
        "references": {
            "ok": r.masked_operand_audit.ok_count,
            "unresolved": r.masked_operand_audit.unresolved_count,
            "mismatch": r.masked_operand_audit.mismatch_count,
        },
        "exact": r.exact,
        "body_byte_exact": r.body_byte_exact,
        "source_sha256": sha((program.config.directory / program.config.source).read_bytes()),
        "object_sha256": sha(program.object_path.read_bytes()),
        "body_sha256": sha(program.body.data),
        "body_bytes": len(program.body.data),
    }


def corrected_source(before):
    old_x = "move_delta.x = (float)cos(random_offset.x);"
    new_x = "float aim_direction_x = (float)cos(random_offset.x);"
    old_use = "scratch_pos.x = move_delta.x * 60.0f + player_position->x;"
    new_use = "scratch_pos.x = aim_direction_x * 60.0f + player_position->x;"
    assert before.count(old_x) == before.count(old_use) == 3
    return before.replace(old_x, new_x).replace(old_use, new_use)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert e.unicorn.__version__ == "2.1.4"
    assert sha(ENGINE.read_bytes()) == ENGINE_SHA
    assert sha(e.match.default_image_path().read_bytes()) == IMAGE_SHA
    config = e.match.load_scratch_config(e.match.DEFAULT_MATCH_ROOT / "scratches/player_update")
    layout = check_layout(config, args.out)
    before = (HERE / "before.cpp").read_text()
    assert sha(before.encode()) == BASELINE_SHA
    assert corrected_source(before) == (config.directory / config.source).read_text()
    before_dir = args.out / "before"
    before_dir.mkdir(exist_ok=True)
    (before_dir / config.source).write_text(before)
    old = e.Program(replace(config, directory=before_dir))
    current = e.Program(config)
    cases = list(scenarios())
    assert len(cases) == 3738 and len({case["name"] for case in cases}) == len(cases)
    (args.out / "cases.json").write_bytes(encoded(cases))
    rows, witnesses, turn_witnesses, differences = [], [], [], []
    coverage = [set(), set(), set()]
    for i, case in enumerate(cases):
        native = run(current, True, case["frame"])
        previous = run(old, False, case["frame"])
        candidate = run(current, False, case["frame"])
        expected = observation(native)
        assert observation(candidate) == expected, case["name"]
        before_equal = observation(previous) == expected
        if not before_equal:
            differences.append(case["name"])
        for j, result in enumerate((native, previous, candidate)):
            coverage[j].update(result["coverage"])
        rows.append(
            {
                "case": case["name"],
                "before_equal": before_equal,
                "calls": len(native["calls"]),
                "native_observation_sha256": sha(encoded(expected)),
                "before_observation_sha256": sha(encoded(observation(previous))),
                "candidate_observation_sha256": sha(encoded(observation(candidate))),
            },
        )
        if case["name"].startswith("point-"):
            frame = case["frame"]
            ax, ay = struct.unpack_from("<2I", bytes.fromhex(native["state"]["players"]), 0x50)
            witnesses.append(
                {
                    "position_x": frame["pos_x"],
                    "position_y": frame["pos_y"],
                    "heading": frame["aim_heading"],
                    "aim_x_bits": ax,
                    "aim_y_bits": ay,
                },
            )
        if case["name"].startswith("turn-"):
            frame = case["frame"]
            ax, ay = struct.unpack_from("<2I", bytes.fromhex(native["state"]["players"]), 0x50)
            turn_witnesses.append(
                {
                    "position_x": frame["pos_x"],
                    "position_y": frame["pos_y"],
                    "heading": frame["aim_heading"],
                    "dt": frame["dt"],
                    "scheme": frame["aim"],
                    "left": frame["input_aim_pov_left_active"],
                    "right": frame["input_aim_pov_right_active"],
                    "aim_x_bits": ax,
                    "aim_y_bits": ay,
                },
            )
        if (i + 1) % 100 == 0:
            print(f"{i + 1}/{len(cases)} agree; before differs in {len(differences)}", flush=True)
    assert {"mode-1-3", "mode-2-3", "mode-5-3", "aim-16", "aim-292", "aim-415", "aim-444", "aim-573"} <= set(
        differences,
    )
    witness_bytes = encoded({"witnesses": witnesses})
    assert len(witnesses) == 1050
    (args.out / "player-aim-point.json").write_bytes(witness_bytes)
    assert witness_bytes == (ROOT / "crimson-zig/src/runtime/testdata/player-aim-point.json").read_bytes()
    assert len(turn_witnesses) == 240
    turn_bytes = encoded({"witnesses": turn_witnesses})
    (args.out / "player-aim-turns.json").write_bytes(turn_bytes)
    assert turn_bytes == (ROOT / "crimson-zig/src/runtime/testdata/player-aim-turns.json").read_bytes()
    manifest = e.match.load_function_manifest(scope="all")
    helpers = {}
    for name in (
        "player_apply_move_with_spawn_avoidance",
        "player_heading_approach_target",
        "vec2_length",
        "vec2_sub",
        "crt_ftol",
    ):
        _, start, end = e.match.resolve_function(manifest, name)
        helpers[name] = {"address": start, "end": end, "sha256": sha(current.image.function_bytes(start, end))}
    result = {
        "schema": 1,
        "precision": "x87 PC=24, round-to-nearest",
        "image_sha256": IMAGE_SHA,
        "engine_sha256": ENGINE_SHA,
        "unicorn_version": e.unicorn.__version__,
        "layout": layout,
        "native_helpers": helpers,
        "before": metrics(old),
        "after": metrics(current),
        "cases": len(cases),
        "before_mismatch_cases": differences,
        "after_mismatch_cases": [],
        "coverage": {
            name: {"instructions": len(pcs), "offsets": sorted(pcs)}
            for name, pcs in zip(("native", "before", "after"), coverage, strict=True)
        },
        "witnesses": len(witnesses),
        "witness_sha256": sha(witness_bytes),
        "turn_witnesses": len(turn_witnesses),
        "turn_witness_sha256": sha(turn_bytes),
        "files": {
            name: sha((HERE / name).read_bytes())
            for name in ("runner.py", "fixtures.py", "layout.py", "verify.py", "before.cpp")
        },
        "results": rows,
    }
    (args.out / "results.json").write_bytes(encoded(result))
    print(
        f"DONE: {len(cases)} agree; before differs in {len(differences)}; {len(witnesses)} native witnesses",
        flush=True,
    )


if __name__ == "__main__":
    main()
