"""Replay one pinned residual candidate with the existing native execution suites."""

import argparse
import hashlib
import importlib.util
import json
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

from recover import BEFORE_SHA, BODY_SHA, STEPS, recover

from crimson import match

HERE = Path(__file__).resolve().parent
IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
KEYS = ("state", "scalars", "calls", "writes", "rng_state")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def family(name, fixture_file="fixtures.py"):
    directory = HERE.parent / (name + "-2026-09-11")
    engine = load(name + "_engine", directory / "execute.py")
    saved = sys.modules.get("execute")
    sys.modules["execute"] = engine
    try:
        fixture = load(name + "_fixtures", directory / fixture_file)
    finally:
        if saved is None:
            del sys.modules["execute"]
        else:
            sys.modules["execute"] = saved
    return engine, fixture


def identity(program):
    result = program.result
    return {
        "source_sha256": sha((program.config.directory / program.config.source).read_bytes()),
        "object_sha256": sha(program.object_path.read_bytes()),
        "body_sha256": sha(program.body.data),
        "build_key": match._scratch_build_key(program.config, match.DEFAULT_MATCH_ROOT),
        "ratio": result.ratio,
        "instructions": len(result.candidate_disassembly),
        "target_instructions": len(result.target_disassembly),
        "references_ok": result.masked_operand_audit.ok_count,
        "reference_problems": result.masked_operand_audit.problem_count,
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
    }


def observation(trace):
    data = {key: {name: value.hex() for name, value in trace[key].items()} for key in ("state", "scalars")}
    data.update({key: trace[key] for key in ("calls", "writes", "rng_state")})
    return sha(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--through", type=int, choices=range(1, len(STEPS) + 1), default=len(STEPS))
    parser.add_argument(
        "--suite",
        required=True,
        choices=("particle-update", "particle-impact", "particle-integrated", "bubble", "movement", "primary"),
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    families = {
        "particle-update": "projectile-particle-update",
        "particle-impact": "projectile-particle-impact",
        "particle-integrated": "projectile-particle-impact",
        "bubble": "particle-bubble-expiry",
        "movement": "primary-microstep-threshold",
        "primary": "primary-impact-template",
    }
    engine, fixture = family(families[args.suite], "verify.py" if args.suite == "bubble" else "fixtures.py")
    # Fixtures also import their engine inside scenario helpers. This standalone
    # process runs exactly one family, so retain that binding through execution.
    sys.modules["execute"] = engine
    assert engine.unicorn.__version__ == "2.1.4"
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    before = (HERE / "before.cpp").read_text()
    assert sha(before.encode()) == BEFORE_SHA
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    programs = {}
    for name, source in (("before", before), ("recovered", recover(before, STEPS[: args.through]))):
        directory = args.out / name
        directory.mkdir(exist_ok=True)
        (directory / "scratch.cpp").write_text(source)
        kwargs = {"integrated": True} if args.suite == "particle-integrated" else {}
        programs[name] = engine.Program(replace(config, directory=directory), **kwargs)
    if args.through == len(STEPS):
        assert sha(programs["recovered"].body.data) == BODY_SHA
    layouts = fixture.check_layout(config, args.out) if hasattr(fixture, "check_layout") else None
    if args.suite in ("particle-impact", "particle-integrated"):
        cases = list(fixture.scenarios(programs["before"]))
        if args.suite == "particle-integrated":
            cases = fixture.integrated_scenarios(cases)
    elif args.suite == "movement":
        cases = [dict(case, fpcw=cw) for cw in (0x7F, 0x37F) for case in fixture.movement_cases()]
    elif args.suite == "primary":
        cases = list(fixture.scenarios(programs["before"], 1000))
    else:
        cases = fixture.scenarios()
    counts = {name: Counter() for name in programs}
    changes, newly_failing = Counter(), Counter()
    rows = []
    for index, case in enumerate(cases):
        native = engine.run(programs["before"], True, case)
        traces = {name: engine.run(program, False, case) for name, program in programs.items()}
        differences = {name: [key for key in KEYS if trace[key] != native[key]] for name, trace in traces.items()}
        for name, diff in differences.items():
            counts[name].update(diff)
        changed = [key for key in KEYS if traces["before"][key] != traces["recovered"][key]]
        changes.update(changed)
        new_failures = [key for key in differences["recovered"] if key not in differences["before"]]
        newly_failing.update(new_failures)
        assert not new_failures, (args.suite, index, new_failures)
        if args.through == len(STEPS) and args.suite != "primary":
            assert not differences["recovered"], (args.suite, index, differences)
        if args.suite in ("primary", "movement", "particle-update", "bubble"):
            assert not changed, (args.suite, index, changed)
        rows.append(
            {
                "index": index,
                "native": observation(native),
                "candidates": {name: observation(trace) for name, trace in traces.items()},
                "differences": differences,
                "changed": changed,
            },
        )
        if index % 200 == 0:
            print(args.suite, index + 1, "/", len(cases), flush=True)
    result = {
        "schema_version": 1,
        "suite": args.suite,
        "steps": STEPS[: args.through],
        "cases": len(cases),
        "cases_sha256": sha(json.dumps(cases, sort_keys=True).encode()),
        "native_image_sha256": IMAGE_SHA,
        "layouts": layouts,
        "identities": {name: identity(program) for name, program in programs.items()},
        "native_difference_counts": {name: dict(count) for name, count in counts.items()},
        "before_after_changed": dict(changes),
        "newly_failing_observations": dict(newly_failing),
        "rows": rows,
        "new_exact_matches": 0,
        "harness_sha256": {
            str(path.relative_to(HERE.parent)): sha(path.read_bytes())
            for path in (HERE / "verify.py", HERE / "recover.py", Path(engine.__file__), Path(fixture.__file__))
        },
        "scope": "Finite native CPU execution with the selected suite's documented helpers and recording boundaries. Full compared pools, globals, writes, calls and RNG; no whole-function equivalence or new matching credit.",
    }
    (args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print("PASS", args.suite, len(cases), result["native_difference_counts"], flush=True)


if __name__ == "__main__":
    main()
