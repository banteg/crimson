"""Run callback regressions with both the saved old and current input-hook bodies."""

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    test_path = ROOT / "tests/debug/test_frida_input_hooks.py"
    spec = importlib.util.spec_from_file_location("hook_tests", test_path)
    tests = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tests)
    checks = [
        ("nested-primary", tests.test_filtered_nested_queries_preserve_primary_helper_context, ()),
        ("nested-and-interleaved", tests.test_tracked_nesting_and_interleaved_threads_keep_distinct_results, ()),
        ("byte-false", tests.test_query_results_use_the_native_boolean_byte, ("grim_is_key_active", 0)),
        ("auto-player-zero", tests.test_accepted_shot_captures_effective_fire_for_its_player, (0, False)),
        ("auto-player-one", tests.test_accepted_shot_captures_effective_fire_for_its_player, (1, True)),
        ("integer-width-control", tests.test_integer_query_result_keeps_its_full_width, (0x100,)),
        ("unrelated-query-control", tests.test_unrelated_query_or_projectile_is_not_effective_fire,
         ("grim_is_key_down", 34, 0x415CEE)),
    ]
    baseline = args.out / "baseline-harness.js"
    baseline.write_text(
        f"const {{createInputHarness}} = require({json.dumps(str(HERE / 'harness.js'))});\n"
        f"const before = require('node:fs').readFileSync({json.dumps(str(HERE / 'before-input-hooks.js'))}, 'utf8');\n"
        "module.exports = {createInputHarness: (source, options) => createInputHarness(source, options, before)};\n",
    )
    results = {}
    for label, harness in (("before", baseline), ("current", HERE / "harness.js")):
        tests.HARNESS = harness
        rows = []
        for name, check, params in checks:
            try:
                check(*params)
            except AssertionError as exc:
                rows.append({"name": name, "passed": False, "assertion": str(exc)})
            else:
                rows.append({"name": name, "passed": True})
        results[label] = rows
    assert all(row["passed"] for row in results["current"]), results
    assert [row["name"] for row in results["before"] if not row["passed"]] == [row[0] for row in checks[:5]], results
    results["sha256"] = {str(path.relative_to(ROOT)): sha(path) for path in (
        ROOT / "scripts/frida/gameplay_diff_capture.js", HERE / "before-input-hooks.js", HERE / "harness.js",
        Path(__file__), test_path,
    )}
    (args.out / "controls.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Current callbacks pass all seven controls; old callbacks fail five and pass both unchanged controls.")


if __name__ == "__main__":
    main()
