"""Replay the preceding Fire/billboard fixtures and type-reload controls."""

import argparse
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
PREVIOUS = HERE.parent / "renderer-position-boundaries-2026-09-13"
spec = importlib.util.spec_from_file_location("position_replay", PREVIOUS / "verify.py")
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
e = previous.e


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    config = replace(
        match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_render"),
        directory=args.out,
    )
    source = args.source.read_text()
    (args.out / config.source).write_text(source)
    program = e.Program(config)
    receipt = json.loads((PREVIOUS / "results.json").read_text())
    assert e.sha(match.default_image_path().read_bytes()) == receipt["image_sha256"]
    assert (
        e.sha(program.image.function_bytes(program.native_start, program.native_end)) == receipt["native_body_sha256"]
    )
    fixture_bytes = (PREVIOUS / "fixtures.jsonl").read_bytes()
    assert e.sha(fixture_bytes) == receipt["fixtures"]["sha256"]
    hashes = []
    for line in fixture_bytes.decode().splitlines():
        row = json.loads(line)
        native, candidate = previous.f.compare(program, row["case"])
        assert native["calls"] == candidate["calls"]
        assert native["pools"] == row["pools"] and native["writes"] == row["writes"]
        assert previous.f.digest(native["calls"]) == row["native_trace_sha256"]
        expected = (
            previous.f.oracle(row["case"], native)
            if row["kind"] == "fire"
            else previous.quad_oracle(row["case"], native)
        )
        assert expected == row["expected"]
        hashes.append(row["native_trace_sha256"])
    assert len(hashes) == 656
    line = "        type_id = projectile->pos.tail.vy.type_id;\n"
    assert source.count(line) == 1
    bad_dir = args.out / "no-reload"
    bad_dir.mkdir(exist_ok=True)
    (bad_dir / config.source).write_text(source.replace(line, ""))
    bad = e.Program(replace(config, directory=bad_dir))
    callbacks = []
    for row in receipt["callbacks"]:
        case, to_type = row["case"], row["to_type"]
        native, events = previous.callback_run(program, True, case, to_type)
        candidate, _ = previous.callback_run(program, False, case, to_type)
        wrong, _ = previous.callback_run(bad, False, case, to_type)
        assert native["calls"] == candidate["calls"] and native["calls"] != wrong["calls"]
        assert native["pools"] == candidate["pools"] == wrong["pools"]
        assert native["writes"] == candidate["writes"] == wrong["writes"]
        assert previous.quad_oracle(case, native, to_type) == row["expected"]
        trace = previous.f.digest(native["calls"])
        assert trace == row["native_trace_sha256"] and events == row["events"]
        callbacks.append(trace)
    assert len(callbacks) == 12
    result = {
        "source_sha256": e.sha(source.encode()),
        "object_sha256": e.sha(program.object_path.read_bytes()),
        "body_sha256": e.sha(program.body.data),
        "verifier_sha256": e.sha(Path(__file__).read_bytes()),
        "previous_verifier_sha256": e.sha((PREVIOUS / "verify.py").read_bytes()),
        "previous_receipt_sha256": e.sha((PREVIOUS / "results.json").read_bytes()),
        "fire_proof_sha256": e.sha(previous.FIRE_PROOF.read_bytes()),
        "executor_sha256": e.sha(previous.f.EXECUTOR.read_bytes()),
        "engine_sha256": e.sha(e.ENGINE.read_bytes()),
        "image_sha256": receipt["image_sha256"],
        "native_body_sha256": receipt["native_body_sha256"],
        "fixtures_sha256": e.sha(fixture_bytes),
        "fixture_count": len(hashes),
        "ordered_trace_sha256": previous.f.digest(hashes),
        "callback_count": len(callbacks),
        "callback_trace_sha256": previous.f.digest(callbacks),
        "no_reload_source_sha256": e.sha((bad_dir / config.source).read_bytes()),
        "unicorn_version": e.unicorn.__version__,
    }
    (args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{len(hashes)} historical position fixtures and {len(callbacks)} callback controls agree.", flush=True)


if __name__ == "__main__":
    main()
