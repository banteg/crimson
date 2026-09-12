"""Replay immutable renderer witnesses against a freshly compiled source."""

import argparse
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

from crimson import match

EVIDENCE = match.DEFAULT_MATCH_ROOT / "evidence"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--suite", choices=["historic", "conventional", "laser"], required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "scratch.cpp").write_bytes(args.source.read_bytes())
    config = replace(
        match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_render"),
        directory=args.out,
    )
    historical = module("historical_replay", EVIDENCE / "secondary-body-rounding-2026-09-11/replay_regressions.py")
    p = historical.probe
    program = p.Program(config)
    image_sha = p.sha(match.default_image_path().read_bytes())
    native_sha = p.sha(program.image.function_bytes(program.native_start, program.native_end))
    packages = []
    if args.suite == "historic":
        for name in (*historical.PACKAGES, "secondary-body-rounding"):
            secondary = name == "secondary-body-rounding"
            path = EVIDENCE / (name + ("-2026-09-11" if secondary else "-2026-09-10")) / "results.json"
            data = json.loads(path.read_text())
            assert data["image_sha256"] == image_sha and data["native_body_sha256"] == native_sha
            hashes = []
            for index, row in enumerate(data["fixtures"]):
                if secondary:
                    native = historical.verify.execute(program, True, row["rows"], row["alpha"], row["glow"])
                    candidate = historical.verify.execute(program, False, row["rows"], row["alpha"], row["glow"])
                    assert native["secondary_state_sha256"] == row["secondary_state_sha256"]
                    assert historical.verify.oracle(native, row["rows"], row["glow"]) == row["body_oracle"]
                else:
                    positional, kw = historical.arguments(name, data, row)
                    native = p.run(program, True, *positional, **kw)
                    candidate = p.run(program, False, *positional, **kw)
                    assert native["state_sha256"] == row["projectile_state_sha256"]
                    for key in ("creature_state_sha256", "player_state_sha256"):
                        if key in row:
                            assert native[key] == row[key]
                historical.verify.same_trace(native, candidate)
                trace = p.sha(json.dumps(native["calls"]).encode())
                assert trace == row["call_trace_sha256"], (name, index)
                hashes.append(trace)
            packages.append(
                {
                    "package": name,
                    "receipt_sha256": p.sha(path.read_bytes()),
                    "cases": len(hashes),
                    "ordered_trace_sha256": p.sha(json.dumps(hashes).encode()),
                },
            )
            print(f"{name}: {len(hashes)} native/candidate traces agree", flush=True)
    else:
        name = "conventional-corner-rounding" if args.suite == "conventional" else "laser-trig-rounding"
        directory = EVIDENCE / (name + "-2026-09-11")
        execute = module(args.suite + "_executor", directory / "execute.py")
        path = directory / "results.json"
        data = json.loads(path.read_text())
        assert data["image_sha256"] == image_sha and data["native_body_sha256"] == native_sha
        fixture = directory / data["fixtures"]["file"]
        assert p.sha(fixture.read_bytes()) == data["fixtures"]["sha256"]
        hashes = []
        for line in fixture.read_text().splitlines():
            row = json.loads(line)
            native = execute.run(program, True, row["case"])
            candidate = execute.run(program, False, row["case"])
            assert native["calls"] == candidate["calls"], row["index"]
            assert native["pools"] == candidate["pools"] == row["pools"]
            assert native["writes"] == candidate["writes"]
            if args.suite == "conventional":
                assert native["writes"] == row["writes"]
            trace = p.sha(json.dumps(native["calls"]).encode())
            key = "call_trace_sha256" if args.suite == "conventional" else "native_trace_sha256"
            assert trace == row[key], row["index"]
            hashes.append(trace)
        assert len(hashes) == data["fixtures"]["count"]
        packages.append(
            {
                "package": name,
                "receipt_sha256": p.sha(path.read_bytes()),
                "fixtures_sha256": p.sha(fixture.read_bytes()),
                "cases": len(hashes),
                "ordered_trace_sha256": p.sha(json.dumps(hashes).encode()),
            },
        )
        print(f"{name}: {len(hashes)} native/candidate traces agree", flush=True)
    negative = None
    if args.suite == "historic":
        source = args.source.read_text()
        assert source.count("arc * effect_scale * 10.0f") == 4
        bad_dir = args.out / "wrong-width"
        bad_dir.mkdir(exist_ok=True)
        (bad_dir / config.source).write_text(source.replace("arc * effect_scale * 10.0f", "arc * effect_scale * 9.0f"))
        bad = p.Program(replace(config, directory=bad_dir))
        receipt = json.loads((EVIDENCE / "ion-chain-product-2026-09-10/results.json").read_text())
        row = next(r for r in receipt["fixtures"] if r["type_id"] == 23 and r["life"] == 0.2)
        positional, kw = historical.arguments("ion-chain-product", receipt, row)
        native = p.run(program, True, *positional, **kw)
        wrong = p.run(bad, False, *positional, **kw)
        assert native["calls"] != wrong["calls"]
        negative = {
            "kind": "wrong-ion-width",
            "source_sha256": p.sha((bad_dir / config.source).read_bytes()),
            "native_trace_sha256": p.sha(json.dumps(native["calls"]).encode()),
            "wrong_trace_sha256": p.sha(json.dumps(wrong["calls"]).encode()),
        }
    record = {
        "source_sha256": p.sha(args.source.read_bytes()),
        "object_sha256": p.sha(program.object_path.read_bytes()),
        "image_sha256": image_sha,
        "native_body_sha256": native_sha,
        "candidate_body_sha256": p.sha(program.body.data),
        "verifier_sha256": p.sha(Path(__file__).read_bytes()),
        "unicorn_version": p.unicorn.__version__,
        "suite": args.suite,
        "packages": packages,
        "negative_control": negative,
        "metrics": match.match_result_payload(program.result),
        "scope": "Recorded caller traces and pool/write state with unchanged modeled external contracts; no GPU or all-input equivalence claim",
    }
    (args.out / "replay.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
