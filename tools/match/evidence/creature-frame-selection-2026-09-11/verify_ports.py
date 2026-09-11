"""Compare current and immutable pre-fix port paths with native PC24 frames."""

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

from crimson.creatures.anim import creature_anim_select_frame
from crimson.creatures.spawn import CreatureFlags

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASELINE = "76a92bf522e3ee8591fcbab324009201683d6dea"
DEFAULT_WITNESSES = ROOT / "crimson-zig/src/runtime/testdata/creature-frame-selection.json"
GIT = shutil.which("git")
ZIG = shutil.which("zig")
assert GIT and ZIG


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def previous(path):
    return subprocess.run([GIT, "show", f"{BASELINE}:{path}"], cwd=ROOT, check=True, capture_output=True).stdout


def differences(witnesses, actual):
    return [
        {"case": witness["case"], "slot": witness["slot"], "native": witness["frame"], "actual": frame}
        for witness, frame in zip(witnesses, actual, strict=True)
        if witness["frame"] != frame
    ]


def zig_frames(root, witnesses, mode):
    command = [
        ZIG,
        "run",
        "-O",
        mode,
        "--dep",
        "app",
        f"-Mroot={HERE / 'ports.zig'}",
        f"-Mapp={root}",
        "--",
        str(witnesses),
    ]
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--witnesses", type=Path, default=DEFAULT_WITNESSES)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    data = json.loads(args.witnesses.read_text())
    assert data["fpcw"] == 0x7F and len(data["witnesses"]) == 2640
    witnesses = data["witnesses"]
    before_python = previous("src/crimson/creatures/anim.py")
    before_file = args.out / "before_anim.py"
    before_file.write_bytes(before_python)
    spec = importlib.util.spec_from_file_location("crimson.creatures.frame_baseline", before_file)
    baseline_python = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline_python)
    current_frames, old_frames = [], []
    for witness in witnesses:
        inputs = {key: witness[key] for key in ("base_frame", "mirror_long")}
        inputs["flags"] = CreatureFlags(witness["flags"])
        phase, stage = witness["phase"], witness["lifecycle_stage"]
        current_frames.append(creature_anim_select_frame(phase, lifecycle_stage=stage, **inputs)[0])
        # Reproduce the exact caller adaptation in BASELINE's world/draw.py.
        if not (witness["flags"] & 4) or witness["flags"] & 64:
            if stage < 0:
                phase = -1.0
            elif stage < 16:
                phase = float(witness["base_frame"] + 15) - stage - 0.5
        inputs["mirror_long"] &= stage >= 16
        old_frames.append(baseline_python.creature_anim_select_frame(phase, **inputs)[0])
    current_python_differences = differences(witnesses, current_frames)
    assert not current_python_differences
    baseline_python_differences = differences(witnesses, old_frames)
    assert len(baseline_python_differences) == 270
    zig_results = []
    for mode in ("Debug", "ReleaseFast"):
        result = zig_frames(ROOT / "crimson-zig/src/root.zig", args.witnesses, mode)
        assert result.returncode == 0, result.stderr
        frames = [int(line) for line in result.stdout.splitlines()]
        assert not differences(witnesses, frames), mode
        zig_results.append({"mode": mode, "count": len(frames), "stdout_sha256": sha(result.stdout.encode())})
        (args.out / f"current-{mode}.txt").write_text(result.stdout)
    # Rebuild the old atlas/animation implementation in a private source copy.
    # All dependencies are unchanged by this fix and supplied by this checkout.
    baseline_root = args.out / "baseline-zig"
    shutil.copytree(ROOT / "crimson-zig/src", baseline_root, dirs_exist_ok=True)
    baseline_hashes = {"src/crimson/creatures/anim.py": sha(before_python)}
    for relative in ("runtime/anim.zig", "window_atlas.zig"):
        path = f"crimson-zig/src/{relative}"
        raw = previous(path)
        baseline_hashes[path] = sha(raw)
        (baseline_root / relative).write_bytes(raw)
    old_caller = previous("src/crimson/render/world/draw.py")
    baseline_hashes["src/crimson/render/world/draw.py"] = sha(old_caller)
    assert b"phase = float(info.base + 0x0F) - lifecycle_stage - 0.5" in old_caller
    # The former signed-mask translation overflows for raw=-16 in Debug.
    # Measure the remaining rows and execute one excluded row separately to
    # preserve the actual panic as evidence, rather than silently dropping it.
    panic_rows, baseline_rows = [], []
    for witness in witnesses:
        is_panic = witness["phase"] == -17.0 and witness["flags"] & 4 and not witness["flags"] & 64
        (panic_rows if is_panic else baseline_rows).append(witness)
    assert len(panic_rows) == 12
    baseline_witnesses = args.out / "baseline-witnesses.json"
    write_json(baseline_witnesses, {**data, "witnesses": baseline_rows})
    old_result = zig_frames(baseline_root / "root.zig", baseline_witnesses, "Debug")
    assert old_result.returncode == 0, old_result.stderr
    old_zig_frames = [int(line) for line in old_result.stdout.splitlines()]
    old_zig_differences = differences(baseline_rows, old_zig_frames)
    assert old_zig_differences
    (args.out / "baseline-Debug.txt").write_text(old_result.stdout)
    panic_witnesses = args.out / "baseline-panic.json"
    write_json(panic_witnesses, {**data, "witnesses": panic_rows[:1]})
    panic = zig_frames(baseline_root / "root.zig", panic_witnesses, "Debug")
    assert panic.returncode != 0 and "integer overflow" in panic.stderr
    (args.out / "baseline-panic.stderr.txt").write_text(panic.stderr)
    result = {
        "schema_version": 1,
        "kind": "native-creature-frame-port-comparison",
        "baseline_commit": BASELINE,
        "baseline_hashes": baseline_hashes,
        "witnesses_sha256": sha(args.witnesses.read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "zig_harness_sha256": sha((HERE / "ports.zig").read_bytes()),
        "zig_version": subprocess.run([ZIG, "version"], check=True, capture_output=True, text=True).stdout.strip(),
        "current_source_hashes": {
            path: sha((ROOT / path).read_bytes())
            for path in (
                "src/crimson/creatures/anim.py",
                "src/crimson/render/world/draw.py",
                "src/crimson/render/world/creatures.py",
            "crimson-zig/src/runtime/anim.zig",
            "crimson-zig/src/window_atlas.zig",
            "crimson-zig/src/root.zig",
            )
        },
        "python": {
            "count": len(witnesses),
            "current_differences": current_python_differences,
            "baseline_differences": baseline_python_differences,
        },
        "zig_current": zig_results,
        "zig_baseline": {
            "mode": "Debug",
            "compared_count": len(baseline_rows),
            "differences": old_zig_differences,
            "excluded_from_frame_comparison": [{"case": row["case"], "slot": row["slot"]} for row in panic_rows],
            "executed_panic_case": panic_rows[0],
            "panic_exit_code": panic.returncode,
            "panic": "integer overflow",
        },
    }
    write_json(args.out / "port-results.json", result)
    print(f"Python: {len(witnesses)} agree, {len(baseline_python_differences)} previous differences")
    print(
        f"Zig: {len(witnesses)} agree in Debug and ReleaseFast, "
        f"{len(old_zig_differences)} previous differences in {len(baseline_rows)} comparable rows; "
        "negative ping-pong panic reproduced",
    )


if __name__ == "__main__":
    main()
