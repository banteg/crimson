"""Reconstruct and freshly compile the bounded renderer source controls."""

import argparse
import concurrent.futures
import hashlib
import json
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def metrics(result):
    return {
        "ratio": result.ratio,
        "ins": len(result.candidate_lines),
        "prefix": result.prefix_instructions,
        "refs": result.masked_operand_audit.ok_count,
        "problems": result.masked_operand_audit.problem_count,
        "exact": result.exact,
        "body": result.body_byte_exact,
    }


def reconstruct(base, control):
    lines = base.splitlines(keepends=True)
    previous = len(lines)
    for edit in reversed(control["edits"]):
        start, stop = edit["start"], edit["stop"]
        assert 0 <= start <= stop <= previous
        assert "".join(lines[start:stop]) == edit["old"]
        lines[start:stop] = edit["new"].splitlines(keepends=True)
        previous = start
    source = "".join(lines)
    assert sha(source.encode()) == control["source_sha256"]
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    data = json.loads((HERE / "source-controls.json").read_text())
    base = (HERE / "before.cpp").read_text()
    assert sha(base.encode()) == data["baseline_sha256"]
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
    assert config.compiler == data["compiler"] and config.cflags == data["cflags"]
    assert json.loads(json.dumps(config.reference_aliases)) == data["reference_aliases"]

    def check(control):
        source = reconstruct(base, control)
        directory = args.out / control["name"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / config.source).write_text(source)
        obj = match.compile_scratch(replace(config, directory=directory), force=True)
        result = match.run_match(
            obj_path=obj,
            function=config.function,
            symbol_name=config.symbol,
            reference_aliases=config.reference_aliases,
        )
        observed = metrics(result)
        assert observed == control["observed"], (control["name"], observed)
        frame = match.match_result_payload(result)["stack_frame"]
        assert frame == control["frame"]
        return {"name": control["name"], "source_sha256": sha(source.encode()), "observed": observed}

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        rows = list(pool.map(check, data["controls"]))
    receipt = {
        "verified_controls": rows,
        "baseline_sha256": sha(base.encode()),
        "controls_sha256": sha((HERE / "source-controls.json").read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "image_sha256": sha(match.default_image_path().read_bytes()),
    }
    (args.out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Verified {len(rows)} compiling controls; no exact-match credit.")


if __name__ == "__main__":
    main()
