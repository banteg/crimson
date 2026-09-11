"""Measure Python and Zig aim-point paths against exported native witnesses."""

import argparse
import ast
import json
import math
import shutil
import struct
import subprocess
from pathlib import Path

from runner import ROOT, e, run
from verify import encoded, sha

from crimson.gameplay import _player_aim_point_from_heading
from crimson.local_input import _aim_point_from_heading
from crimson.math_parity import NATIVE_HALF_PI, f32, native_aim_point_from_heading, x87_pc24_sub
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2

HERE = Path(__file__).resolve().parent
BASELINE = "c5b5aff659e43b75b792c83f6a2557cd342471d1"
WITNESSES = ROOT / "crimson-zig/src/runtime/testdata/player-aim-point.json"


def previous(path):
    return subprocess.check_output([shutil.which("git") or "git", "show", f"{BASELINE}:{path}"], cwd=ROOT)


def function(source, name):
    node = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == name)
    return ast.get_source_segment(source, node)


def bits(point):
    return list(struct.unpack("<2I", struct.pack("<2f", point.x, point.y)))


def zig_points(root, mode):
    command = [
        shutil.which("zig") or "zig",
        "run",
        "-O",
        mode,
        "--dep",
        "app",
        f"-Mroot={HERE / 'ports.zig'}",
        f"-Mapp={root}",
        "--",
        str(WITNESSES),
    ]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout, [list(map(int, line.split())) for line in result.stdout.splitlines()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    rows = json.loads(WITNESSES.read_text())["witnesses"]
    assert len(rows) == 1050
    expected = [[row["aim_x_bits"], row["aim_y_bits"]] for row in rows]
    old_gameplay = previous("src/crimson/gameplay.py")
    old_input = previous("src/crimson/local_input.py")
    scope = {
        "Vec2": Vec2,
        "PlayerState": PlayerState,
        "math": math,
        "f32": f32,
        "NATIVE_HALF_PI": NATIVE_HALF_PI,
        "x87_pc24_sub": x87_pc24_sub,
        "_AIM_POINT_RADIUS": 60.0,
        "_AIM_RADIUS_KEYBOARD": 60.0,
    }
    old_functions = "\n\n".join(
        [
            function(old_gameplay.decode(), "_direction_from_heading_native"),
            function(old_gameplay.decode(), "_player_aim_point_from_heading"),
            function(old_input.decode(), "_aim_point_from_heading"),
        ],
    )
    exec(old_functions, scope)  # noqa: S102 - exact functions from the pinned local baseline commit.
    (args.out / "before_python_functions.py").write_text(old_functions + "\n")
    differences = {
        name: []
        for name in (
            "before_gameplay_stored_f32",
            "before_input_stored_f32",
            "before_gameplay_python_values",
            "before_input_python_values",
        )
    }
    for i, row in enumerate(rows):
        position = Vec2(row["position_x"], row["position_y"])
        player = PlayerState(index=0, pos=position)
        heading = row["heading"]
        expected_point = struct.unpack("<2f", struct.pack("<2I", *expected[i]))
        for point in (
            native_aim_point_from_heading(position, heading),
            _aim_point_from_heading(position, heading),
            _player_aim_point_from_heading(player, heading),
        ):
            assert bits(point) == expected[i] and (point.x, point.y) == expected_point, i
        for name, point in (
            ("gameplay", scope["_player_aim_point_from_heading"](player, heading)),
            ("input", scope["_aim_point_from_heading"](position, heading)),
        ):
            if bits(point) != expected[i]:
                differences[f"before_{name}_stored_f32"].append(i)
            if (point.x, point.y) != expected_point:
                differences[f"before_{name}_python_values"].append(i)
    baseline_root = args.out / "baseline-zig"
    shutil.copytree(ROOT / "crimson-zig/src", baseline_root, dirs_exist_ok=True)
    old_zig = previous("crimson-zig/src/local_input.zig")
    (baseline_root / "local_input.zig").write_bytes(old_zig)
    zig_results = []
    for name, root in (("before", baseline_root / "root.zig"), ("current", ROOT / "crimson-zig/src/root.zig")):
        for mode in ("Debug", "ReleaseFast"):
            stdout, points = zig_points(root, mode)
            assert len(points) == len(rows)
            bad = [i for i, (got, want) in enumerate(zip(points, expected, strict=True)) if got != want]
            assert (len(bad) == len(rows)) if name == "before" else not bad
            (args.out / f"{name}-{mode}.txt").write_text(stdout)
            zig_results.append(
                {
                    "source": name,
                    "mode": mode,
                    "count": len(points),
                    "mismatch_indices": bad,
                    "stdout_sha256": sha(stdout.encode()),
                },
            )
            print(f"{name} Zig {mode}: {len(bad)}/{len(rows)} differ", flush=True)
    # Pin the exact replacement values used by the existing POV input tests.
    program = e.Program(e.match.load_scratch_config(e.match.DEFAULT_MATCH_ROOT / "scratches/player_update"))
    result = run(
        program,
        True,
        {
            "aim": 2,
            "movement": 0,
            "dt": 0.1,
            "pos_x": 100,
            "pos_y": 100,
            "aim_heading": 0,
            "input_aim_pov_right_active": True,
        },
    )
    pov = list(struct.unpack_from("<2I", bytes.fromhex(result["state"]["players"]), 0x50))
    assert pov == [1123465966, 1110635010]
    paths = [
        "src/crimson/math_parity.py",
        "src/crimson/gameplay.py",
        "src/crimson/local_input.py",
        "crimson-zig/src/runtime/native_math.zig",
        "crimson-zig/src/local_input.zig",
        "crimson-zig/src/root.zig",
        "tests/gameplay/test_player_aim_native.py",
        "tests/input/test_local_input.py",
    ]
    report = {
        "schema": 1,
        "baseline_commit": BASELINE,
        "witness_count": len(rows),
        "witness_sha256": sha(WITNESSES.read_bytes()),
        "python_current_mismatches": 0,
        "python_before": differences,
        "zig": zig_results,
        "pov_right_dt_0_1_native_aim_bits": pov,
        "baseline_files": {
            "src/crimson/gameplay.py": sha(old_gameplay),
            "src/crimson/local_input.py": sha(old_input),
            "crimson-zig/src/local_input.zig": sha(old_zig),
        },
        "current_files": {path: sha((ROOT / path).read_bytes()) for path in paths},
        "harness_files": {name: sha((HERE / name).read_bytes()) for name in ("verify_ports.py", "ports.zig")},
    }
    (args.out / "port-results.json").write_bytes(encoded(report))
    print({name: len(indices) for name, indices in differences.items()}, flush=True)


if __name__ == "__main__":
    main()
