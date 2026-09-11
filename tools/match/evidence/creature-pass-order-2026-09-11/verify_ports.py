"""Compare native witnesses with the actual old/current Python and Zig draw paths."""

import argparse
import hashlib
import importlib.util
import json
import math
import shutil
import struct
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
BASELINE = "c8c9cda9922d15a5f95c00ca1247994dd52e51bc"
WITNESSES = ROOT / "crimson-zig/src/runtime/testdata/creature-pass-order.json"
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
            fields = [name for name in ("pass", "index", "type_id", "frame") if native[name] != draw[name]]
            sizes = struct.unpack("<2f", struct.pack("<2I", *native["quad_bits"][2:]))
            for name, size in zip(("width", "height"), sizes, strict=True):
                if not math.isclose(draw[name], size, rel_tol=1e-6 if native["pass"] == "shadow" else 0, abs_tol=0):
                    fields.append(name)
            if fields:
                failures.append({"case": case, "draw": index, "fields": fields, "actual": draw, "expected": native})
    return failures


def summarize(witnesses, draws, failures):
    # Match dimensions by creature/pass independently of ordering failures.
    size_failures = []
    order_cases = []
    for ordinal, (witness, records) in enumerate(zip(witnesses, draws, strict=True)):
        expected = {(row["pass"], row["index"]): row for row in witness["expected"]}
        if [(row["pass"], row["index"]) for row in records] != [
            (row["pass"], row["index"]) for row in witness["expected"]
        ]:
            order_cases.append(ordinal)
        for record in records:
            native = expected[record["pass"], record["index"]]
            sizes = struct.unpack("<2f", struct.pack("<2I", *native["quad_bits"][2:]))
            if any(
                not math.isclose(record[name], size, rel_tol=1e-6 if native["pass"] == "shadow" else 0, abs_tol=0)
                for name, size in zip(("width", "height"), sizes, strict=True)
            ):
                size_failures.append({"case": ordinal, "pass": record["pass"], "index": record["index"]})
    return {
        "count": len(failures),
        "case_count": len({row["case"] for row in failures}),
        "ordered_sequence_cases": order_cases,
        "dimension_mismatches_aligned_by_creature": len(size_failures),
        "dimension_mismatches_sha256": sha(json.dumps(size_failures).encode()),
        "all_differences_sha256": sha(json.dumps(failures).encode()),
        "first_five_differences": failures[:5],
    }


def extracted(source):
    functions = {}
    for name in FUNCTIONS:
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
            draws = [capture_creature_draws(row["input"], texture_size=size, **options) for row in witnesses]
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
                    case, batch, index, kind, frame, width, height = line.split()
                    draws[int(case)].append(
                        {
                            "pass": batch,
                            "index": int(index),
                            "type_id": int(kind),
                            "frame": int(frame),
                            "width": float(width),
                            "height": float(height),
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
