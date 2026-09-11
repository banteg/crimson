"""Check both runtime ports against the native grid observations.

This checks formation count, positions, target offsets, type, health, heading,
links and RNG state. Python phase seeds are checked too; the Zig CLI omits them
and its dedicated runtime regression checks them separately.
"""

import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path

from crimson.creatures.spawn import SpawnEnv, SpawnId, build_spawn_plan
from grim.geom import Vec2
from grim.rand import Crand

ROOT = Path(__file__).resolve().parents[4]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bits(value):
    return struct.pack("<f", value).hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-results", required=True, type=Path)
    parser.add_argument("--zig-binary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    binary = args.zig_binary.resolve()
    native_bytes = args.native_results.read_bytes()
    record = json.loads(native_bytes)
    rows = []
    skipped = []
    for witness in record["grid_witnesses"]:
        case = witness["input"]
        if case.get("fpcw", 0x7F) != 0x7F:
            skipped.append({"case": witness["case"], "reason": "Runtime arithmetic uses PC24"})
            continue  # Runtime arithmetic models the game's PC24 mode.
        if case.get("retry", 0) < 0:
            skipped.append({"case": witness["case"], "reason": "Zig CLI rejects negative retry counts"})
            continue
        position = case.get("position", [150.25, 350.5])
        heading = case.get("heading", -100.0)
        rng = Crand(case["seed"])
        env = SpawnEnv(
            terrain_width=1024,
            terrain_height=1024,
            demo_mode_active=bool(case.get("demo", 0)),
            hardcore=bool(case.get("hardcore", 0)),
            quest_fail_retry_count=case.get("retry", 0),
        )
        plan = build_spawn_plan(SpawnId(case["template"]), Vec2(*position), heading, rng, env)
        assert len(plan.creatures) == 28 and plan.primary == 27
        assert rng.state == witness["rng_state"]
        command = [
            str(binary),
            "spawn-plan",
            hex(case["template"]),
            "--json",
            "--seed",
            str(case["seed"]),
            f"--pos={position[0]},{position[1]}",
            f"--heading={heading}",
            "--demo-mode-active" if env.demo_mode_active else "--no-demo-mode-active",
            "--quest-fail-retry-count",
            str(env.quest_fail_retry_count),
        ]
        if env.hardcore:
            command.append("--hardcore")
        zig_bytes = subprocess.run(command, check=True, capture_output=True).stdout
        zig = json.loads(zig_bytes)
        assert zig["active_count"] == 28 and zig["rng_state"] == witness["rng_state"]
        for index, (native, python, zig_creature) in enumerate(
            zip(witness["creatures"], plan.creatures, zig["creatures"], strict=True),
        ):
            assert python.phase_seed == native["phase_seed"]
            assert int(python.type_id) == native["type_id"] == zig_creature["type_id"]
            for field, py_value, zig_value in (
                ("pos_x", python.pos.x, zig_creature["pos"]["x"]),
                ("pos_y", python.pos.y, zig_creature["pos"]["y"]),
                ("health", python.health, zig_creature["health"]),
                ("heading", python.heading, zig_creature["heading"]),
            ):
                assert bits(py_value) == bits(native[field]) == bits(zig_value), (
                    case,
                    index,
                    field,
                    native[field],
                    py_value,
                    zig_value,
                )
            if index:
                assert python.ai_link_parent == native["link_index"] == zig_creature["link_index"] == 0
                for component in ("x", "y"):
                    assert (
                        bits(getattr(python.target_offset, component))
                        == bits(native[f"target_offset_{component}"])
                        == bits(zig_creature["target_offset"][component])
                    )
                assert bits(python.max_health) == bits(native["max_health"]) == bits(zig_creature["max_health"])
        rows.append(
            {
                "case": witness["case"],
                "template": case["template"],
                "creatures": 28,
                "rng_state": rng.state,
                "zig_output_sha256": sha(zig_bytes),
            },
        )
    assert {row["template"] for row in rows} == set(range(0x14, 0x19))
    result = {
        "schema_version": 1,
        "native_results_sha256": sha(native_bytes),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "zig_binary_sha256": sha(binary.read_bytes()),
        "source_sha256": {
            name: sha((ROOT / name).read_bytes())
            for name in (
                "src/crimson/creatures/spawn.py",
                "crimson-zig/src/runtime/creatures.zig",
                "crimson-zig/src/spawn_plan_native.zig",
            )
        },
        "cases": len(rows),
        "skipped": skipped,
        "rows": rows,
    }
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"Both ports passed {len(rows)} native grid cases")


if __name__ == "__main__":
    main()
