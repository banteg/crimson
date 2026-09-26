"""Replay pinned renderer fixtures and a zero-alpha corruption control."""

import argparse
import hashlib
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(value):
    return sha(json.dumps(value, sort_keys=True).encode())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def historic(config, out):
    history = module("history", EVIDENCE / "secondary-body-rounding-2026-09-11/replay_regressions.py")
    engine = history.probe
    program = engine.Program(config)
    image_sha = sha(match.default_image_path().read_bytes())
    native_sha = sha(program.image.function_bytes(program.native_start, program.native_end))
    packages = []
    negative_case = None
    for name in (*history.PACKAGES, "secondary-body-rounding"):
        secondary = name == "secondary-body-rounding"
        path = EVIDENCE / (name + ("-2026-09-11" if secondary else "-2026-09-10")) / "results.json"
        data = json.loads(path.read_text())
        assert data["image_sha256"] == image_sha and data["native_body_sha256"] == native_sha
        hashes = []
        for row in data["fixtures"]:
            if secondary:
                native = history.verify.execute(program, True, row["rows"], row["alpha"], row["glow"])
                candidate = history.verify.execute(program, False, row["rows"], row["alpha"], row["glow"])
                assert native["secondary_state_sha256"] == row["secondary_state_sha256"]
                assert history.verify.oracle(native, row["rows"], row["glow"]) == row["body_oracle"]
            else:
                positional, keywords = history.arguments(name, data, row)
                if negative_case is None:
                    negative_case = positional, keywords
                native = engine.run(program, True, *positional, **keywords)
                candidate = engine.run(program, False, *positional, **keywords)
                assert native["state_sha256"] == row["projectile_state_sha256"]
                for key in ("creature_state_sha256", "player_state_sha256"):
                    if key in row:
                        assert native[key] == row[key]
            history.verify.same_trace(native, candidate)
            trace = sha(json.dumps(native["calls"]).encode())
            assert trace == row["call_trace_sha256"]
            hashes.append(trace)
        packages.append(
            {
                "name": name,
                "receipt_sha256": sha(path.read_bytes()),
                "cases": len(hashes),
                "ordered_trace_sha256": digest(hashes),
            },
        )
        print(name, len(hashes), "agree", flush=True)

    source = (config.directory / config.source).read_text()
    anchor = "trail_tint(0.5f, 0.5f, 0.5f, 0.0f)"
    assert source.count(anchor) == 1
    wrong_dir = out / "wrong-alpha"
    wrong_dir.mkdir()
    wrong_source = source.replace(anchor, "trail_tint(0.5f, 0.5f, 0.5f, 0.25f)")
    (wrong_dir / config.source).write_text(wrong_source)
    wrong = engine.Program(replace(config, directory=wrong_dir))
    positional, keywords = negative_case
    native = engine.run(program, True, *positional, **keywords)
    bad = engine.run(wrong, False, *positional, **keywords)
    assert len(native["calls"]) == len(bad["calls"])
    changed = [i for i, (a, b) in enumerate(zip(native["calls"], bad["calls"], strict=True)) if a != b]
    assert len(changed) == 2
    assert all(native["calls"][i][0] == "grim_set_color_slot" for i in changed)
    return program, {
        "packages": packages,
        "cases": sum(row["cases"] for row in packages),
        "negative_control": {
            "kind": "alpha-is-quarter",
            "source_sha256": sha(wrong_source.encode()),
            "changed_calls": changed,
            "native": digest(native["calls"]),
            "wrong": digest(bad["calls"]),
        },
        "harness_sha256": sha((EVIDENCE / "secondary-body-rounding-2026-09-11/replay_regressions.py").read_bytes()),
    }


def positions(config):
    directory = EVIDENCE / "renderer-position-boundaries-2026-09-13"
    prior = module("positions", directory / "verify.py")
    program = prior.e.Program(config)
    receipt = json.loads((directory / "results.json").read_text())
    fixture = directory / "fixtures.jsonl"
    assert sha(fixture.read_bytes()) == receipt["fixtures"]["sha256"]
    assert sha(match.default_image_path().read_bytes()) == receipt["image_sha256"]
    assert sha(program.image.function_bytes(program.native_start, program.native_end)) == receipt["native_body_sha256"]
    hashes = []
    for line in fixture.read_text().splitlines():
        row = json.loads(line)
        native, candidate = prior.f.compare(program, row["case"])
        assert native["calls"] == candidate["calls"]
        assert native["pools"] == row["pools"] and native["writes"] == row["writes"]
        assert prior.f.digest(native["calls"]) == row["native_trace_sha256"]
        expected = (
            prior.f.oracle(row["case"], native) if row["kind"] == "fire" else prior.quad_oracle(row["case"], native)
        )
        assert expected == row["expected"]
        hashes.append(row["native_trace_sha256"])
    assert len(hashes) == 656
    callbacks = []
    for row in receipt["callbacks"]:
        native, events = prior.callback_run(program, True, row["case"], row["to_type"])
        candidate, _ = prior.callback_run(program, False, row["case"], row["to_type"])
        assert native["calls"] == candidate["calls"]
        assert native["pools"] == candidate["pools"] and native["writes"] == candidate["writes"]
        assert prior.f.digest(native["calls"]) == row["native_trace_sha256"] and events == row["events"]
        callbacks.append(row["native_trace_sha256"])
    assert len(callbacks) == 12
    print("positions", len(hashes), "and", len(callbacks), "callback cases agree", flush=True)
    return program, {
        "cases": len(hashes),
        "callback_cases": len(callbacks),
        "ordered_trace_sha256": digest(hashes),
        "callback_trace_sha256": digest(callbacks),
        "fixtures_sha256": sha(fixture.read_bytes()),
        "harness_sha256": sha((directory / "verify.py").read_bytes()),
    }


def ion(config):
    directory = EVIDENCE / "ion-endpoint-rounding-2026-09-13"
    prior = module("ion", directory / "verify.py")
    program = prior.p.Program(config)
    receipt = json.loads((directory / "results.json").read_text())
    fixture = directory / "fixtures.jsonl"
    assert sha(fixture.read_bytes()) == receipt["fixtures"]["sha256"]
    assert sha(match.default_image_path().read_bytes()) == receipt["image_sha256"]
    assert sha(program.image.function_bytes(program.native_start, program.native_end)) == receipt["native_body_sha256"]
    hashes = []
    for line in fixture.read_text().splitlines():
        row = json.loads(line)
        native = prior.run(program, True, row["case"])
        candidate = prior.run(program, False, row["case"])
        assert native["calls"] == candidate["calls"]
        assert all(native[key] == candidate[key] == row["state"][key] for key in prior.STATE_KEYS)
        trace = sha(json.dumps(native["calls"]).encode())
        assert trace == row["native_trace_sha256"]
        endpoint = native["calls"][native["return_sites"].index(0x424F86)]
        assert endpoint == ["grim_draw_quad", prior.endpoint_oracle(row["case"])]
        hashes.append(trace)
    assert len(hashes) == 524
    print("ion", len(hashes), "agree", flush=True)
    return program, {
        "cases": len(hashes),
        "ordered_trace_sha256": digest(hashes),
        "fixtures_sha256": sha(fixture.read_bytes()),
        "harness_sha256": sha((directory / "verify.py").read_bytes()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--suite", choices=("historic", "positions", "ion"), required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    (args.out / "scratch.cpp").write_bytes(args.source.read_bytes())
    config = replace(
        match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_render"), directory=args.out,
    )
    program, details = historic(config, args.out) if args.suite == "historic" else globals()[args.suite](config)
    import unicorn

    assert unicorn.__version__ == "2.1.4"
    result = {
        "suite": args.suite,
        "source_sha256": sha(args.source.read_bytes()),
        "body_sha256": sha(program.body.data),
        "object_sha256": sha(program.object_path.read_bytes()),
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "unicorn_version": unicorn.__version__,
        "details": details,
        "scope": "Finite native caller traces and modeled external contracts; no GPU or arbitrary-input equivalence claim.",
    }
    (args.out / "receipt.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
