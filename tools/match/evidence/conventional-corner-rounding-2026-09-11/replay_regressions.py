"""Replay the five preceding projectile-render proof packages without rewriting them."""

import argparse
import importlib.util
import json
from pathlib import Path

import execute
from verify import BEFORE_SHA

HERE = Path(__file__).resolve().parent
REPLAY = HERE.parent / "secondary-body-rounding-2026-09-11/replay_regressions.py"
SPEC = importlib.util.spec_from_file_location("previous_renderer_replay", REPLAY)
previous = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(previous)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert execute.unicorn.__version__ == "2.1.4"
    config = execute.match.load_scratch_config(execute.match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
    program = execute.Program(config)
    image_sha = execute.sha(execute.match.default_image_path().read_bytes())
    native_sha = execute.sha(program.image.function_bytes(program.native_start, program.native_end))
    results = []
    for name in (*previous.PACKAGES, "secondary-body-rounding"):
        secondary = name == "secondary-body-rounding"
        directory = name + ("-2026-09-11" if secondary else "-2026-09-10")
        path = HERE.parent / directory / "results.json"
        receipt = json.loads(path.read_text())
        assert receipt["image_sha256"] == image_sha and receipt["native_body_sha256"] == native_sha
        assert receipt["source_sha256"] == (BEFORE_SHA if secondary else previous.verify.BEFORE_SHA)
        fixtures = []
        for index, row in enumerate(receipt["fixtures"]):
            if secondary:
                native = previous.verify.execute(program, True, row["rows"], row["alpha"], row["glow"])
                candidate = previous.verify.execute(program, False, row["rows"], row["alpha"], row["glow"])
                assert native["secondary_state_sha256"] == row["secondary_state_sha256"]
                assert previous.verify.oracle(native, row["rows"], row["glow"]) == row["body_oracle"]
            else:
                positional, keywords = previous.arguments(name, receipt, row)
                native = previous.probe.run(program, True, *positional, **keywords)
                candidate = previous.probe.run(program, False, *positional, **keywords)
                assert native["state_sha256"] == row["projectile_state_sha256"]
                for key in ("creature_state_sha256", "player_state_sha256"):
                    if key in row:
                        assert native[key] == row[key]
            previous.verify.same_trace(native, candidate)
            trace_sha = execute.sha(json.dumps(native["calls"]).encode())
            assert trace_sha == row["call_trace_sha256"], (name, index, "Historical native trace changed")
            fixtures.append(
                {
                    "index": index,
                    "call_trace_sha256": trace_sha,
                    "native_instructions_exercised": native["coverage"],
                    "candidate_instructions_exercised": candidate["coverage"],
                },
            )
        results.append({"package": directory, "receipt_sha256": execute.sha(path.read_bytes()), "fixtures": fixtures})
        print(f"Verified {name}: {len(fixtures)} historical native traces", flush=True)
    record = {
        "schema_version": 1,
        "kind": "renderer-fixture-regression-replay",
        "new_source_matches": 0,
        "source_sha256": execute.sha((config.directory / config.source).read_bytes()),
        "verifier_sha256": execute.sha(Path(__file__).read_bytes()),
        "previous_replay_sha256": execute.sha(REPLAY.read_bytes()),
        "secondary_verifier_sha256": execute.sha((REPLAY.parent / "verify.py").read_bytes()),
        "engine_sha256": execute.sha(execute.ENGINE.read_bytes()),
        "image_sha256": image_sha,
        "native_body_sha256": native_sha,
        "candidate_object_sha256": execute.sha(program.object_path.read_bytes()),
        "candidate_body_sha256": execute.sha(program.body.data),
        "results": results,
        "scope": "same inputs and external-call recording contracts as the five immutable historical receipts",
    }
    (out / "regressions.json").write_text(json.dumps(record, indent=2) + "\n")


if __name__ == "__main__":
    main()
