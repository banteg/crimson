"""Compare native witnesses with the actual old/current Python and Zig draw paths."""

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(ROOT))
from tests.support.creature_draw_capture import capture_creature_draws

GIT = shutil.which("git")
ZIG = shutil.which("zig")
assert GIT and ZIG
BASELINE = "4e9ef68d2464228c4b67fd4db87bf0972f032a47"
WITNESSES = ROOT / "crimson-zig/src/runtime/testdata/creature-render-colors.json"
FUNCTIONS = (
    "drawCreatures",
    "drawCreatureHitFlashes",
    "creatureRenderTint",
    "drawAtlasFrameCenteredRotated",
    "radiansToDegrees",
    "colorWithAlpha",
    "colorFromUnitRgba",
    "alphaByte",
    "toRlVec",
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def old(path):
    return subprocess.check_output([GIT, "show", f"{BASELINE}:{path}"], cwd=ROOT)


def previous_python(out):
    modules = []
    for name in ("creatures", "draw"):
        path = f"src/crimson/render/world/{name}.py"
        before = out / f"before_{name}.py"
        before.write_bytes(old(path))
        spec = importlib.util.spec_from_file_location(f"crimson.render.world._previous_{name}", before)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module.__name__] = module
        spec.loader.exec_module(module)
        modules.append(module)
    modules[1].draw_creature_sprite = modules[0].draw_creature_sprite
    return modules[1]


def differences(witnesses, actual):
    failures = []
    for case, (witness, draws) in enumerate(zip(witnesses, actual, strict=True)):
        expected = witness["expected"]
        if len(draws) != len(expected):
            failures.append({"case": case, "reason": "count", "actual": len(draws), "expected": len(expected)})
        for index, (native, draw) in enumerate(zip(expected, draws)):
            fields = [name for name in ("pass", "index", "frame") if native[name] != draw[name]]
            packed = native["packed_color"]
            rgba = [(packed >> shift) & 255 for shift in (16, 8, 0, 24)]
            # Native ZERO/INVSRCALPHA ignores source RGB; Raylib uses black.
            if native["pass"] == "shadow":
                rgba[:3] = [0, 0, 0]
            if draw["rgba"] != rgba:
                fields.append("rgba")
            if fields:
                failures.append({"case": case, "draw": index, "fields": fields, "actual": draw, "expected": native})
    return failures


def summarize(witnesses, draws, failures):
    return {
        "count": len(failures),
        "case_count": len({row["case"] for row in failures}),
        "pass_counts": {
            batch: sum(row.get("actual", {}).get("pass") == batch for row in failures)
            for batch in ("shadow", "body", "flash")
        },
        "all_differences_sha256": sha(json.dumps(failures).encode()),
        "first_five_differences": failures[:5],
    }


def extracted(source):
    functions = {}
    for name in FUNCTIONS:
        if name == "creatureRenderTint" and f"fn {name}(" not in source:
            continue
        start = source.index(f"fn {name}(")
        end = source.index("\n}\n", start) + 3
        functions[name] = source[start:end]
    return functions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    witnesses = json.loads(WITNESSES.read_bytes())["cases"]
    python_results = []
    previous = previous_python(out)
    for label, options in (("previous", {"module": previous}), ("current", {})):
        for size in (256, 512):
            draws = [
                capture_creature_draws(row["input"], texture_size=size, include_color=True, **options)
                for row in witnesses
            ]
            failures = differences(witnesses, draws)
            assert bool(failures) == (label == "previous"), (label, size, failures[:1])
            python_results.append(
                {
                    "side": label,
                    "texture_size": size,
                    "draws": sum(map(len, draws)),
                    "draws_sha256": sha(json.dumps(draws).encode()),
                    "differences": summarize(witnesses, draws, failures),
                },
            )
    zig_results = []
    functions_hashes = {}
    for label in ("previous", "current"):
        path = "crimson-zig/src/window_main.zig"
        raw = old(path) if label == "previous" else (ROOT / path).read_bytes()
        functions = extracted(raw.decode())
        functions_hashes[label] = {name: sha(value.encode()) for name, value in functions.items()}
        source = (HERE / "ports.zig").read_text() + "\n" + "\n".join(functions.values())
        generated = out / f"{label}.zig"
        generated.write_text(source)
        for mode in ("Debug", "ReleaseFast"):
            for size in (256, 512):
                command = [
                    ZIG,
                    "run",
                    "-O",
                    mode,
                    "--dep",
                    "app",
                    f"-Mroot={generated}",
                    f"-Mapp={ROOT / 'crimson-zig/src/root.zig'}",
                    "--",
                    str(WITNESSES),
                    str(size),
                ]
                run = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
                assert run.returncode == 0, run.stderr
                draws = [[] for _ in witnesses]
                for line in run.stdout.splitlines():
                    case, batch, index, kind, frame, width, height, r, g, b, a = line.split()
                    draws[int(case)].append(
                        {
                            "pass": batch,
                            "index": int(index),
                            "type_id": int(kind),
                            "frame": int(frame),
                            "width": float(width),
                            "height": float(height),
                            "rgba": [int(r), int(g), int(b), int(a)],
                        },
                    )
                failures = differences(witnesses, draws)
                assert bool(failures) == (label == "previous"), (label, mode, size, failures[:1])
                zig_results.append(
                    {
                        "side": label,
                        "mode": mode,
                        "texture_size": size,
                        "draws": sum(map(len, draws)),
                        "stdout_sha256": sha(run.stdout.encode()),
                        "source_sha256": sha(source.encode()),
                        "differences": summarize(witnesses, draws, failures),
                    },
                )
    paths = (
        Path(__file__),
        HERE / "ports.zig",
        ROOT / "tests/support/creature_draw_capture.py",
        ROOT / "src/crimson/render/world/draw.py",
        ROOT / "src/crimson/render/world/creatures.py",
        ROOT / "crimson-zig/src/window_main.zig",
        ROOT / "crimson-zig/src/window_atlas.zig",
        ROOT / "crimson-zig/src/runtime/anim.zig",
        ROOT / "crimson-zig/src/runtime/native_math.zig",
    )
    result = {
        "baseline_commit": BASELINE,
        "witnesses_sha256": sha(WITNESSES.read_bytes()),
        "files": {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in paths},
        "zig_version": subprocess.check_output([ZIG, "version"], text=True).strip(),
        "extracted_functions": functions_hashes,
        "python": python_results,
        "zig": zig_results,
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    for language in ("python", "zig"):
        print(
            language,
            [
                (row["side"], row["texture_size"], row.get("mode"), row["draws"], row["differences"]["count"])
                for row in result[language]
            ],
        )


if __name__ == "__main__":
    main()
