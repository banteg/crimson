"""Check native movement boundaries, ion-chain arguments, and prior trajectories."""

import argparse
import copy
import hashlib
import importlib.util
import json
import random
import sys
from collections import Counter
from dataclasses import replace
from pathlib import Path

import execute as chain
from recover import BEFORE_SHA, RECOVERED_BODY_SHA, recover

HERE = Path(__file__).resolve().parent
KEYS = ("state", "scalars", "calls", "writes", "rng_state")
IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def family(name):
    directory = HERE.parent / (name + "-2026-09-11")
    engine = load(name + "_engine", directory / "execute.py")
    saved = sys.modules.get("execute")
    sys.modules["execute"] = engine
    try:
        fixtures = load(name + "_fixtures", directory / "fixtures.py")
    finally:
        if saved is None:
            del sys.modules["execute"]
        else:
            sys.modules["execute"] = saved
    return engine, fixtures


def identity(program):
    result = program.result
    return {
        "source_sha256": sha((program.config.directory / program.config.source).read_bytes()),
        "object_sha256": sha(program.object_path.read_bytes()),
        "body_sha256": sha(program.body.data),
        "build_key": chain.match._scratch_build_key(program.config, chain.match.DEFAULT_MATCH_ROOT),
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


def chain_cases():
    rng = random.Random(2026091301)
    for _ in range(500):
        x, y = (chain.m.f32(rng.uniform(-60, 1000)) for _ in range(2))
        nx = chain.m.f32(x + rng.choice((-1, 1)) * rng.uniform(120, 750))
        ny = chain.m.f32(y + rng.choice((-1, 1)) * rng.uniform(120, 750))
        case = {
            "dt": 0.01,
            "shock_id": 0,
            "shock_links": 3,
            "rng_seed": 19,
            "violence_disabled": 1,
            "primary": [
                {
                    "index": 0,
                    "x": x,
                    "y": y,
                    "origin_x": x - 100,
                    "origin_y": y - 100,
                    "type": 0x15,
                    "life": 1,
                    "speed": 0,
                    "travel": 3,
                    "owner": -100,
                    "radius": 1,
                    "damage": 100,
                },
            ],
            "creatures": [
                {"index": 0, "x": x, "y": y, "health": 1000, "max_health": 1000, "size": 40, "lifecycle": 16},
                {"index": 1, "x": nx, "y": ny, "health": 1000, "max_health": 1000, "size": 40, "lifecycle": 16},
            ],
        }
        for control_word in (0x7F, 0x37F):
            result = copy.deepcopy(case)
            result["fpcw"] = control_word
            yield result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--suite",
        choices=("movement", "chain", "particle-update", "particle-impact", "primary"),
        required=True,
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert chain.unicorn.__version__ == "2.1.4"
    assert sha(chain.match.default_image_path().read_bytes()) == IMAGE_SHA
    before = (HERE / "before.cpp").read_text()
    assert sha(before.encode()) == BEFORE_SHA
    config = chain.match.load_scratch_config(chain.match.DEFAULT_MATCH_ROOT / "scratches/projectile_update")
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    assert recover(before) == (config.directory / config.source).read_text()
    engines = {
        "movement": "primary-microstep-threshold",
        "particle-update": "projectile-particle-update",
        "particle-impact": "projectile-particle-impact",
        "primary": "primary-impact-template",
    }
    engine, fixtures = (chain, None) if args.suite == "chain" else family(engines[args.suite])
    programs = {}
    masks = (0, 1, 2, 3) if args.suite == "movement" else (0, 3)
    for mask in masks:
        directory = args.out / str(mask)
        directory.mkdir(exist_ok=True)
        (directory / "scratch.cpp").write_text(recover(before, mask))
        programs[mask] = engine.Program(replace(config, directory=directory))
    assert sha(programs[3].body.data) == RECOVERED_BODY_SHA
    if args.suite == "movement":
        cases = []
        for control_word in (0x7F, 0x37F):
            for case in fixtures.movement_cases():
                case = copy.deepcopy(case)
                case["fpcw"] = control_word
                cases.append(case)
    elif args.suite == "chain":
        cases = list(chain_cases())
    elif args.suite == "particle-update":
        cases = fixtures.scenarios()
    elif args.suite == "particle-impact":
        cases = list(fixtures.scenarios(programs[0]))
    else:
        cases = list(fixtures.scenarios(programs[0], 1000))
    counts = {mask: Counter() for mask in masks}
    rows = []
    witnesses = []
    for index, case in enumerate(cases):
        native = engine.run(programs[0], True, case)
        actual = {mask: engine.run(program, False, case) for mask, program in programs.items()}
        differences = {}
        for mask, trace in actual.items():
            differences[mask] = [key for key in KEYS if trace[key] != native[key]]
            counts[mask].update(differences[mask])
        if args.suite == "movement":
            assert not differences[3], (index, differences)
            if differences[0]:
                witnesses.append({"case": case, "native_calls": native["calls"], "before_calls": actual[0]["calls"]})
        else:
            assert all(actual[0][key] == actual[3][key] for key in KEYS), (args.suite, index, differences)
        if args.suite == "chain":
            spawn = lambda trace: [call for call in trace["calls"] if call[0] == "projectile_spawn"]
            assert len(spawn(native)) == 1
            assert spawn(native) == spawn(actual[3]), (index, spawn(native), spawn(actual[3]))
        rows.append(
            {
                "index": index,
                "native": observation(native),
                "candidates": {mask: observation(trace) for mask, trace in actual.items()},
                "differences": differences,
            },
        )
        if index % 200 == 0:
            print(args.suite, index + 1, "/", len(cases), flush=True)
    if args.suite == "movement":
        expected = {"calls": 4, "writes": 4, "state": 2}
        assert dict(counts[0]) == dict(counts[2]) == expected
        assert not counts[1] and not counts[3]
    record = {
        "schema_version": 1,
        "suite": args.suite,
        "cases": len(cases),
        "cases_sha256": sha(json.dumps(cases, sort_keys=True).encode()),
        "native_image_sha256": IMAGE_SHA,
        "identities": {mask: identity(program) for mask, program in programs.items()},
        "native_difference_counts": {mask: dict(count) for mask, count in counts.items()},
        "rows": rows,
        "boundary_witnesses": witnesses,
        "harness_sha256": {
            str(path.relative_to(HERE.parent)): sha(path.read_bytes())
            for path in (HERE / "verify.py", HERE / "recover.py", Path(engine.__file__))
        },
        "new_exact_matches": 0,
        "scope": "Finite CPU execution with explicit callback models. RNG values and order are compared; raw native and relocated caller addresses are not equated. Existing unrelated native differences remain recorded.",
    }
    (args.out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print("PASS", args.suite, len(cases), {mask: dict(count) for mask, count in counts.items()}, flush=True)


if __name__ == "__main__":
    main()
