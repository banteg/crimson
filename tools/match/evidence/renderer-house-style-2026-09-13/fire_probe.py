"""Expose the unresolved Fire Bullets coordinate-store boundary."""

import argparse
import importlib.util
import json
import random
from dataclasses import replace
from pathlib import Path

from crimson import match

parser = argparse.ArgumentParser()
parser.add_argument("--source", type=Path, required=True)
parser.add_argument("--out", type=Path, required=True)
args = parser.parse_args()
args.out.mkdir(parents=True, exist_ok=True)
executor = match.DEFAULT_MATCH_ROOT / "evidence/conventional-corner-rounding-2026-09-11/execute.py"
spec = importlib.util.spec_from_file_location("fire_executor", executor)
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
# Only inactive slot 95 may contain type 45; active records remain conventional.
e.TYPES = (*e.TYPES, 45)
(args.out / "scratch.cpp").write_bytes(args.source.read_bytes())
c = replace(match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_render"), directory=args.out)
p = e.Program(c)
rng = random.Random(0x4253BB)
cases = []
for _i in range(256):
    position = [e.f32(rng.uniform(-512, 512)) for _ in range(2)]
    camera = [e.f32(rng.uniform(-512, 512)) for _ in range(2)]
    for cw in (0x007F, 0x037F):
        cases.append(
            {
                "records": [
                    {
                        "index": 3,
                        "type_id": 1,
                        "active": 1,
                        "position": position,
                        "origin": [0.0, 0.0],
                        "velocity": [1.0, 2.0],
                        "angle": e.f32(0.3),
                        "life": e.f32(0.4),
                    },
                    {
                        "index": 95,
                        "type_id": 45,
                        "active": 0,
                        "position": [0.0, 0.0],
                        "origin": [0.0, 0.0],
                        "velocity": [0.0, 0.0],
                        "angle": 0.0,
                        "life": 0.0,
                    },
                ],
                "camera": camera,
                "fpcw": cw,
                "alpha": e.f32(0.7),
                "glow": 0,
            },
        )
failures = []
for i, case in enumerate(cases):
    native = e.run(p, True, case)
    candidate = e.run(p, False, case)
    assert native["pools"] == candidate["pools"] and native["writes"] == candidate["writes"]
    n = [args for name, args in native["calls"] if name == "grim_draw_quad" and args[2:] == [e.bits(64.0)] * 2]
    assert len(n) == 1
    if native["calls"] != candidate["calls"]:
        differences = [
            (j, a, b) for j, (a, b) in enumerate(zip(native["calls"], candidate["calls"], strict=True)) if a != b
        ]
        failures.append({"index": i, "case": case, "differences": differences})
result = {
    "source_sha256": e.sha(args.source.read_bytes()),
    "cases": len(cases),
    "failures": failures,
    "verifier_sha256": e.sha(Path(__file__).read_bytes()),
    "executor_sha256": e.sha(executor.read_bytes()),
    "engine_sha256": e.sha(e.ENGINE.read_bytes()),
    "image_sha256": e.sha(match.default_image_path().read_bytes()),
    "native_body_sha256": e.sha(p.image.function_bytes(p.native_start, p.native_end)),
    "candidate_body_sha256": e.sha(p.body.data),
    "object_sha256": e.sha(p.object_path.read_bytes()),
    "unicorn_version": e.unicorn.__version__,
    "scope": "512 deterministic Fire Bullets overlay witnesses. Only inactive slot 95 may use type 45; all active records use the unchanged conventional executor contracts. Diagnostic PC64 and game PC24, modeled external calls, no GPU proof.",
}
(args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps({"cases": len(cases), "failed": len(failures), "first": failures[:1]}), flush=True)
