"""Replay prior projectile fixtures against the before/recovered C++ sources."""

import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from dataclasses import replace
from pathlib import Path

import execute
from execute import Program, match, run
from recover import recover

HERE = Path(__file__).resolve().parent
KEYS = ("state", "scalars", "calls", "writes", "rng_state")


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, HERE.parent / relative)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert execute.unicorn.__version__ == "2.1.4"
    assert hashlib.sha256(match.default_image_path().read_bytes()).hexdigest() == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    before = (HERE / "before.cpp").read_text()
    assert (
        hashlib.sha256(before.encode()).hexdigest()
        == "29ced950a9a07ed4972859045889678b2d6bceaded5a482c92b5dc2ab8bd23f0"
    )
    configs = []
    for name, source in (("before", before), ("recovered", recover(before))):
        directory = out / name
        directory.mkdir(exist_ok=True)
        (directory / "scratch.cpp").write_text(source)
        configs.append(replace(config, directory=directory))
    programs = [Program(c) for c in configs]
    nohit = load("prior_particle_nohit", "projectile-particle-update-2026-09-11/fixtures.py")
    impacts = load("prior_particle_impacts", "projectile-particle-impact-2026-09-11/fixtures.py")
    primary = load("prior_primary_movement", "primary-microstep-threshold-2026-09-11/fixtures.py")
    particle_cases = impacts.scenarios(programs[0])
    report = {"suites": {}}

    def check_suite(name, cases, engine=execute, integrated=False, native_exact=False):
        pair = [engine.Program(c, integrated=integrated) for c in configs]
        count = 0
        for count, case in enumerate(cases, 1):
            old, new = (engine.run(p, False, case) for p in pair)
            for key in KEYS:
                assert old[key] == new[key], (name, count - 1, key)
            if native_exact:
                native = engine.run(pair[0], True, case)
                for key in KEYS:
                    assert native[key] == new[key], (name, count - 1, "native", key)
        report["suites"][name] = {
            "cases": count,
            "before_recovered_matches": count,
            "native_exact_checked": native_exact,
        }
        print(name, json.dumps(report["suites"][name]), flush=True)
        (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")

    check_suite("particle-no-hit", nohit.scenarios(), native_exact=True)
    check_suite("particle-impact", particle_cases)
    check_suite("particle-integrated-impact", impacts.integrated_scenarios(particle_cases), integrated=True)
    movement_witnesses = []
    for index, case in enumerate(primary.movement_cases()):
        trace = run(programs[0], True, case)
        queries = [
            list(struct.unpack("<2f", struct.pack("<2I", *call[1])))
            for call in trace["calls"]
            if call[0] == "creature_find_in_radius"
        ]
        movement_witnesses.append({"index": index, "input": case, "creature_queries": queries})
    movement_cases = [row["input"] for row in movement_witnesses]
    movement_cases.extend(primary.player_cases(movement_witnesses))
    check_suite("primary-microsteps", movement_cases, native_exact=True)
    bubble_engine = load("prior_bubble_execute", "particle-bubble-expiry-2026-09-11/execute.py")
    bubble = load("prior_bubble_fixtures", "particle-bubble-expiry-2026-09-11/verify.py")
    check_suite("inactive-bubble-expiry", bubble.scenarios(), engine=bubble_engine, native_exact=True)
    expected = {
        "particle-no-hit": 4817,
        "particle-impact": 1230,
        "particle-integrated-impact": 663,
        "primary-microsteps": 605,
        "inactive-bubble-expiry": 224,
    }
    assert {name: row["cases"] for name, row in report["suites"].items()} == expected


if __name__ == "__main__":
    main()
