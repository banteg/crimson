"""Replay all recorded conventional corners after the laser source correction."""

import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PREVIOUS = HERE.parent / "conventional-corner-rounding-2026-09-11"
SPEC = importlib.util.spec_from_file_location("conventional_executor", PREVIOUS / "execute.py")
execute = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(execute)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    receipt_path = PREVIOUS / "results.json"
    receipt = json.loads(receipt_path.read_text())
    fixture_path = PREVIOUS / receipt["fixtures"]["file"]
    assert execute.sha(fixture_path.read_bytes()) == receipt["fixtures"]["sha256"]
    config = execute.match.load_scratch_config(execute.match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
    program = execute.Program(config)
    image_sha = execute.sha(execute.match.default_image_path().read_bytes())
    native_sha = execute.sha(program.image.function_bytes(program.native_start, program.native_end))
    assert receipt["image_sha256"] == image_sha and receipt["native_body_sha256"] == native_sha
    hashes = []
    for line in fixture_path.read_text().splitlines():
        row = json.loads(line)
        native = execute.run(program, True, row["case"])
        candidate = execute.run(program, False, row["case"])
        assert native["calls"] == candidate["calls"]
        assert native["pools"] == candidate["pools"] == row["pools"]
        assert native["writes"] == candidate["writes"] == row["writes"]
        assert [a for n, a in native["calls"] if n == "grim_draw_quad_points"] == row["corners"]
        trace_sha = execute.sha(json.dumps(native["calls"]).encode())
        assert trace_sha == row["call_trace_sha256"]
        hashes.append(trace_sha)
    assert len(hashes) == receipt["fixtures"]["count"] == 4118
    record = {
        "schema_version": 1,
        "kind": "conventional-corner-regression-replay",
        "new_source_matches": 0,
        "source_sha256": execute.sha((config.directory / config.source).read_bytes()),
        "verifier_sha256": execute.sha(Path(__file__).read_bytes()),
        "executor_sha256": execute.sha((PREVIOUS / "execute.py").read_bytes()),
        "program_loader_sha256": execute.sha(execute.ENGINE.read_bytes()),
        "image_sha256": image_sha,
        "native_body_sha256": native_sha,
        "candidate_body_sha256": execute.sha(program.body.data),
        "candidate_object_sha256": execute.sha(program.object_path.read_bytes()),
        "previous_receipt_sha256": execute.sha(receipt_path.read_bytes()),
        "previous_fixture_sha256": execute.sha(fixture_path.read_bytes()),
        "fixture_count": len(hashes),
        "ordered_native_trace_hashes_sha256": execute.sha(json.dumps(hashes).encode()),
        "scope": "All recorded native argument bits, corner words, pool hashes, and writes; unchanged external recording contracts",
    }
    (out / "conventional-regression.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"{len(hashes)} historical conventional native traces agree.")


if __name__ == "__main__":
    main()
