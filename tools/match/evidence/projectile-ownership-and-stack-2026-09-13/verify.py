"""Verify the accumulated candidate through native caller and helper executions."""

import argparse
import importlib.util
import json
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

from recover import recover, sha

from crimson import match

HERE = Path(__file__).resolve().parent
IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
KEYS = ("state", "scalars", "calls", "writes", "rng_state")
FAMILIES = {
    "particle-update": "projectile-particle-update",
    "particle-impact": "projectile-particle-impact",
    "particle-integrated": "projectile-particle-impact",
    "bubble": "particle-bubble-expiry",
    "movement": "primary-microstep-threshold",
    "primary": "primary-impact-template",
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def observation(trace):
    data = {key: {name: value.hex() for name, value in trace[key].items()} for key in ("state", "scalars")}
    data.update({key: trace[key] for key in ("calls", "writes", "rng_state")})
    return sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--suite",
        choices=(*FAMILIES, "primary-weapons", "rocket-impact", "explosion", "steering", "trail"),
        required=True,
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    expanded = args.suite not in FAMILIES
    directory = (
        HERE.parent / "projectile-primary-secondary-residuals-2026-09-13"
        if expanded
        else HERE.parent / (FAMILIES[args.suite] + "-2026-09-11")
    )
    engine_path = directory / "execute.py"
    fixture_path = directory / ("verify.py" if args.suite == "bubble" else "fixtures.py")
    if args.suite in ("steering", "trail"):
        fixture_path = HERE / "fixtures.py"
    engine = load("residual_engine", engine_path)
    sys.modules["execute"] = engine
    fixture = load("residual_fixture", fixture_path)
    assert engine.unicorn.__version__ == "2.1.4"
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    graph = json.loads((HERE / "experiments.json").read_text())
    before = (HERE / "before.cpp").read_text()
    assert sha(before.encode()) == graph["before_source_sha256"]
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    programs = {}
    for name, source in (("before", before), ("recovered", recover())):
        scratch = args.out / name
        scratch.mkdir(exist_ok=True)
        (scratch / "scratch.cpp").write_text(source)
        kwargs = {"integrated": True} if args.suite == "particle-integrated" else {}
        programs[name] = engine.Program(replace(config, directory=scratch), **kwargs)
    assert sha(programs["recovered"].body.data) == graph["experiments"][graph["final"]]["body_sha256"]
    layouts = fixture.check_layout(config, args.out) if hasattr(fixture, "check_layout") else None
    if args.suite in ("particle-impact", "particle-integrated"):
        cases = list(fixture.scenarios(programs["before"]))
        if args.suite == "particle-integrated":
            cases = fixture.integrated_scenarios(cases)
    elif args.suite == "movement":
        cases = [dict(case, fpcw=cw) for cw in (0x7F, 0x37F) for case in fixture.movement_cases()]
    elif args.suite == "primary":
        cases = list(fixture.scenarios(programs["before"], 1000))
    elif args.suite == "rocket-impact":
        cases = list(fixture.rocket_cases(programs["before"], 300))
    elif args.suite in ("steering", "trail"):
        cases = list(fixture.steering_cases(args.suite, 1200))
    elif expanded:
        cases = list(fixture.scenarios(programs["before"], args.suite, 576 if args.suite == "primary-weapons" else 192))
    else:
        cases = list(fixture.scenarios())
    counts = {name: Counter() for name in programs}
    changes, coverage, rows = Counter(), set(), []
    for index, case in enumerate(cases):
        native = engine.run(programs["before"], True, case)
        coverage.update(native.get("coverage", ()))
        traces = {name: engine.run(program, False, case) for name, program in programs.items()}
        differences = {name: [key for key in KEYS if trace[key] != native[key]] for name, trace in traces.items()}
        for name, diff in differences.items():
            counts[name].update(diff)
        assert not differences["recovered"], (args.suite, index, differences)
        changed = [key for key in KEYS if traces["before"][key] != traces["recovered"][key]]
        changes.update(changed)
        row = {
            "index": index,
            "native": observation(native),
            "candidates": {name: observation(trace) for name, trace in traces.items()},
            "differences": differences,
            "changed": changed,
        }
        rows.append(row)
        if index % 200 == 0:
            print(args.suite, index + 1, "/", len(cases), flush=True)
    identities = {}
    for name, program in programs.items():
        result = program.result
        identities[name] = {
            "source_sha256": sha((program.config.directory / program.config.source).read_bytes()),
            "object_sha256": sha(program.object_path.read_bytes()),
            "body_sha256": sha(program.body.data),
            "instructions": len(result.candidate_disassembly),
            "target_instructions": len(result.target_disassembly),
            "references_ok": result.masked_operand_audit.ok_count,
            "reference_problems": result.masked_operand_audit.problem_count,
            "exact": result.exact,
            "body_byte_exact": result.body_byte_exact,
            "build_key": match._scratch_build_key(program.config, match.DEFAULT_MATCH_ROOT),
        }
    record = {
        "schema_version": 1,
        "suite": args.suite,
        "cases": len(cases),
        "cases_sha256": sha(json.dumps(cases, sort_keys=True).encode()),
        "native_image_sha256": IMAGE_SHA,
        "identities": identities,
        "layouts": layouts,
        "native_difference_counts": {name: dict(count) for name, count in counts.items()},
        "before_after_changed": dict(changes),
        "native_coverage_offsets": sorted(coverage),
        "rows": rows,
        "rows_sha256": sha(json.dumps(rows, sort_keys=True).encode()),
        "harness_sha256": {
            str(path.relative_to(match.REPO_ROOT)): sha(path.read_bytes())
            for path in (*HERE.glob("*.py"), HERE / "experiments.json", HERE / "before.cpp", engine_path, fixture_path)
        },
        "new_exact_matches": 0,
        "scope": "See README for each suite's real helper and recording boundaries. Expanded suites model external D3DX normalization; they do not execute the DLL.",
    }
    (args.out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print("PASS", args.suite, len(cases), record["native_difference_counts"], flush=True)


if __name__ == "__main__":
    main()
