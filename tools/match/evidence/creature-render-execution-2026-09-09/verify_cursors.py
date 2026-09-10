"""Check historical cursor-loop failures and the corrected native cursor combination."""

import argparse
import importlib.util
import json
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("render_execution", HERE / "verify.py")
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)


def apply_plan(source, path):
    plan = json.loads(path.read_text())
    for site in plan["sites"]:
        assert source.count(site["find"]) == 1
        source = source.replace(site["find"], site["replacements"][0]["text"])
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    out = parser.parse_args().out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert audit.unicorn.__version__ == "2.1.4"
    match = audit.match
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / audit.FUNCTION)
    source = (config.directory / config.source).read_text()
    layout = audit.check_fixture_layout(config, out)
    plans = {
        "historical-main": "main-animation-cursor-mutations.json",
        "historical-flash": "flash-lifecycle-cursor-mutations.json",
        "corrected": "safe-native-cursors-2026-09-10.json",
    }
    records = {}
    for name, filename in plans.items():
        path = config.directory / filename
        variant = apply_plan(source, path)
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_text(variant)
        object_path = match.compile_scratch(replace(config, directory=directory))
        comparison = audit.Comparison(config, object_path)
        record = {
            "source_sha256": audit.sha(variant.encode()),
            "plan_sha256": audit.sha(path.read_bytes()),
            "object_sha256": audit.sha(object_path.read_bytes()),
            "candidate_body_sha256": audit.sha(comparison.body.data),
        }
        if name != "corrected":
            case = {
                "shadows": 0,
                "flash": int(name == "historical-flash"),
                "energizer": 0.0,
                "creatures": [{"index": 383}],
            }
            native = comparison.execute("native", case)
            try:
                comparison.execute("candidate", case)
            except AssertionError as error:
                if str(error) != "Instruction/time limit reached before return":
                    raise
            else:
                raise AssertionError(f"Historical non-advancing cursor unexpectedly returned: {name}")
            record.update(
                case=case,
                native_returned=True,
                native_calls=len(native["calls"]),
                candidate_failure="Instruction/time limit reached before return",
            )
        else:
            cases = list(audit.scenarios())
            (out / "cases.json").write_text(json.dumps(cases, indent=2) + "\n")
            coverage = [set(), set()]
            for index, case in enumerate(cases):
                result = comparison.compare(case)
                assert result["calls_equal"] and result["writes_equal"], (index, case)
                for side_index, side in enumerate(("native", "candidate")):
                    coverage[side_index].update(result[side]["coverage"])
            result = match.run_match(
                obj_path=object_path,
                function=audit.FUNCTION,
                symbol_name=config.symbol,
                reference_aliases=config.reference_aliases,
            )
            expected = [
                {instruction.offset for instruction in instructions}
                for instructions in (result.target_disassembly, result.candidate_disassembly)
            ]
            assert coverage == expected
            assert not result.exact and not result.body_byte_exact
            payload = match.match_result_payload(result)
            record.update(
                scenarios=len(cases),
                calls_equal=True,
                writes_equal=True,
                cases_sha256=audit.sha((out / "cases.json").read_bytes()),
                all_native_instructions_executed=len(coverage[0]),
                all_candidate_instructions_executed=len(coverage[1]),
                match={
                    key: payload[key]
                    for key in (
                        "exact",
                        "body_byte_exact",
                        "match_ratio",
                        "prefix_instructions",
                        "target_instructions",
                        "candidate_instructions",
                        "references",
                    )
                },
            )
        records[name] = record
        print(name, "verified", flush=True)
    result = {
        "schema_version": 1,
        "function": audit.FUNCTION,
        "unicorn": audit.unicorn.__version__,
        "source_sha256": audit.sha(source.encode()),
        "image_sha256": audit.sha(match.default_image_path().read_bytes()),
        "verifier_sha256": audit.sha(Path(__file__).read_bytes()),
        "execution_verifier_sha256": audit.sha((HERE / "verify.py").read_bytes()),
        "compiler": config.compiler,
        "cflags": config.cflags,
        "compiler_files_sha256": {
            name: audit.sha((match.DEFAULT_MATCH_ROOT / "compilers" / config.compiler / "Bin" / name).read_bytes())
            for name in ("CL.EXE", "C1.DLL", "C1XX.DLL", "C2.DLL")
        },
        "layout": layout,
        "variants": records,
        "new_source_matches": 0,
    }
    (out / "cursor-results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
