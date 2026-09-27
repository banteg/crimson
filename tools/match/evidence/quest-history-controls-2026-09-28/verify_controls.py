"""Rebuild the bounded timeline controls without changing the canonical scratch."""

import argparse
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
SCRATCH = match.DEFAULT_MATCH_ROOT / "scratches/quest_spawn_timeline_update"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def compile_case(case, source, config, out):
    previous = len(source)
    for edit in reversed(case["edits"]):
        assert 0 <= edit["start"] <= edit["end"] <= previous
        source = source[: edit["start"]] + edit["text"] + source[edit["end"] :]
        previous = edit["start"]
    assert sha(source.encode()) == case["source_sha256"]
    directory = out / case["name"]
    directory.mkdir()
    (directory / config.source).write_text(source)
    (directory / "scratch.conf").write_bytes((SCRATCH / "scratch.conf").read_bytes())
    local = replace(config, directory=directory)
    obj = match.compile_scratch(local, match.DEFAULT_MATCH_ROOT.resolve())
    image, functions, metadata = match._paths_for_image(local.image)
    result = match.run_match(
        obj_path=obj,
        function=local.function,
        image_path=image,
        functions_path=functions,
        metadata_path=metadata,
        symbol_name=local.symbol,
        object_extent=local.archive_extent,
        object_end_symbol=local.archive_end_symbol,
        object_size=local.archive_size,
        end_va=local.end_va,
        reference_aliases=local.reference_aliases,
    )
    audit = result.masked_operand_audit
    references = [audit.ok_count, audit.unresolved_count, audit.mismatch_count]
    assert result.ratio == case["expected_ratio"]
    assert len(result.candidate_lines) == case["expected_instructions"]
    assert references == case["expected_references"]
    assert not result.exact and not result.body_byte_exact
    body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), local.symbol)
    (directory / "diff.txt").write_text("\n".join(result.diff_lines()) + "\n")
    return {
        "name": case["name"],
        "source_sha256": case["source_sha256"],
        "body_sha256": sha(body.data),
        "match_ratio": result.ratio,
        "prefix": result.prefix_instructions,
        "instructions": len(result.candidate_lines),
        "references": references,
        "body_byte_exact": result.body_byte_exact,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    spec = json.loads((HERE / "controls.json").read_text())
    source = (SCRATCH / "scratch.cpp").read_text()
    assert sha(source.encode()) == spec["source_sha256"]
    config = match.load_scratch_config(SCRATCH)
    with ThreadPoolExecutor(max_workers=6) as pool:
        rows = list(pool.map(lambda case: compile_case(case, source, config, args.out), spec["cases"]))
    baseline = next(row for row in rows if row["source_sha256"] == spec["source_sha256"])
    assert len(rows) == 60
    same = sum(row["body_sha256"] == baseline["body_sha256"] for row in rows)
    assert same == 50
    assert max(row["match_ratio"] for row in rows) == baseline["match_ratio"]
    receipt = {
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "controls_sha256": sha((HERE / "controls.json").read_bytes()),
        "config_sha256": sha((SCRATCH / "scratch.conf").read_bytes()),
        "image_sha256": sha(match.default_image_path().read_bytes()),
        "canonical_source_sha256": spec["source_sha256"],
        "baseline_body_sha256": baseline["body_sha256"],
        "cases": rows,
        "summary": {"cases_including_baseline": len(rows), "same_body": same, "regressions": 60 - same, "improvements": 0},
        "scope": "Stock compiler source controls; no unretained candidate is claimed behaviorally equivalent.",
    }
    (args.out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(receipt["summary"])


if __name__ == "__main__":
    main()
