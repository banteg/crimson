"""Compare two unpromoted index-owner controls with the historical native fixtures."""

import argparse
import json
import sys
from pathlib import Path

import verify_controls as controls

HERE = Path(__file__).resolve().parent
REPLAY = HERE.parent / "conventional-corner-rounding-2026-09-11"
sys.path.insert(0, str(REPLAY))
import replay_regressions as replay


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    assert replay.execute.unicorn.__version__ == "2.1.4"
    programs, identities = {}, {}
    for name in ("byte-offset-int", "creature-pointer"):
        config, control = controls.reconstruct("projectile_render", name, args.out)
        program = replay.execute.Program(config)
        assert replay.execute.sha(program.body.data) == control["body_sha256"]
        programs[name] = program
        identities[name] = {key: control[key] for key in ("source_sha256", "body_sha256")}
    receipt_path = HERE.parent / "ion-chain-product-2026-09-10/results.json"
    receipt = json.loads(receipt_path.read_text())
    program = programs["byte-offset-int"]
    image_sha = replay.execute.sha(controls.match.default_image_path().read_bytes())
    native_sha = replay.execute.sha(program.image.function_bytes(program.native_start, program.native_end))
    assert image_sha == receipt["image_sha256"]
    assert native_sha == receipt["native_body_sha256"]
    records = []
    for index, row in enumerate(receipt["fixtures"]):
        positional, keywords = replay.previous.arguments("ion-chain-product", receipt, row)
        native = replay.previous.probe.run(program, True, *positional, **keywords)
        assert replay.execute.sha(json.dumps(native["calls"]).encode()) == row["call_trace_sha256"]
        assert native["state_sha256"] == row["projectile_state_sha256"]
        for key in ("creature_state_sha256", "player_state_sha256"):
            if key in row:
                assert native[key] == row[key]
        for candidate_program in programs.values():
            candidate = replay.previous.probe.run(candidate_program, False, *positional, **keywords)
            replay.previous.verify.same_trace(native, candidate)
        records.append({"index": index, "native_trace_sha256": row["call_trace_sha256"],
                        "variants_agree": list(programs)})
        if index % 100 == 0:
            print(f"Verified {index} native ion fixtures", flush=True)
    result = {
        "schema_version": 1,
        "kind": "unpromoted-ion-index-owner-controls",
        "new_source_matches": 0,
        "scope": "The parent's 384 PC=64 ion-chain fixtures, native creature search and recording graphics callbacks; no arbitrary-input or pixel equivalence claim.",
        "identities": identities,
        "image_sha256": image_sha,
        "native_body_sha256": native_sha,
        "verifier_sha256": replay.execute.sha(Path(__file__).read_bytes()),
        "receipt_sha256": replay.execute.sha(receipt_path.read_bytes()),
        "engine_sha256": replay.execute.sha(replay.execute.ENGINE.read_bytes()),
        "replay_sha256": replay.execute.sha((REPLAY / "replay_regressions.py").read_bytes()),
        "fixtures": records,
        "count": len(records),
    }
    (args.out / "ion-validation.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"All {len(records)} native fixtures agree for both controls", flush=True)


if __name__ == "__main__":
    main()
