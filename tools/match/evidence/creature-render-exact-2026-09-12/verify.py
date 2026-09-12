"""Verify the exact creature renderer with the existing native execution fixtures."""

import argparse
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent / "creature-render-execution-2026-09-09/verify.py"
spec = importlib.util.spec_from_file_location("creature_execution", PARENT)
parent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parent)
match, sha = parent.match, parent.sha
BEFORE_SHA = "64c270c898ac14e21ab7ad932cc0cf83a5bdc7d97b397461b102ff93276f7086"
CURRENT_SHA = "ccc5b0965304ef83c444bfae3b091e640802411d0f2c65231f907653e9ed0107"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/creature_render_type")
    assert sha((config.directory / config.source).read_bytes()) == CURRENT_SHA
    before = (HERE / "before.cpp").read_bytes()
    assert sha(before) == BEFORE_SHA
    assert (
        sha(match.default_image_path().read_bytes())
        == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    )

    # The original harness checks layout, complete instruction coverage, CPU
    # observations and four deliberately incorrect source controls.
    parent.main()
    record = json.loads((out / "results.json").read_text())
    assert record["match"]["exact"] and record["match"]["body_byte_exact"]
    assert record["match"]["references_ok"] == 145
    assert record["match"]["references_problem"] == 0
    assert len(record["instruction_coverage"]["native"]) == len(record["instruction_coverage"]["candidate"]) == 765
    cases = list(parent.scenarios())
    assert len(cases) == len(record["scenarios"]) == 130

    directory = out / "before"
    directory.mkdir(exist_ok=True)
    (directory / config.source).write_bytes(before)
    before_config = replace(config, directory=directory)
    object_path = match.compile_scratch(before_config)
    comparison = parent.Comparison(before_config, object_path)
    coverage = set()
    for index, case in enumerate(cases):
        execution = comparison.execute("candidate", case)
        native = record["scenarios"][index]
        assert sha(json.dumps(execution["calls"]).encode()) == native["calls_sha256"], index
        assert sha(json.dumps(execution["writes"]).encode()) == native["writes_sha256"], index
        coverage.update(execution["coverage"])
    result = match.run_match(
        obj_path=object_path,
        function=config.function,
        symbol_name=config.symbol,
        reference_aliases=config.reference_aliases,
    )
    assert coverage == {instruction.offset for instruction in result.candidate_disassembly}
    assert len(coverage) == 760 and not result.exact and not result.body_byte_exact
    record["recovery"] = {
        "before_source_sha256": BEFORE_SHA,
        "current_source_sha256": CURRENT_SHA,
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "execution_verifier_sha256": sha(PARENT.read_bytes()),
        "before_match": match.match_result_payload(result),
        "before_instruction_coverage": sorted(coverage),
        "native_before_current_cases": len(cases),
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Verified exact 765-instruction body, 145 references, and 130 native/before/current cases")


if __name__ == "__main__":
    main()
