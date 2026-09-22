"""Replay all creature fixtures against the prior and pool-base sources.

Diagnostic evidence only: finite native x86 observations under the existing
callback models, not whole-game equivalence.
"""

import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
BEFORE_SHA = "b27f450cd219a514e9083ddfb87842a3a960130f6d5343b851ae6f7835b9ddae"
AFTER_SHA = "7bb97911b09a9e96d60b4b7b93530f07702d92de55d343d75fb5b642b49f44bd"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


fixtures = module("pool_base_fixtures", HERE.parent / "creature-retarget-distance-2026-09-13/verify.py")
legacy = fixtures.legacy
engine = fixtures.engine


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    assert engine.unicorn.__version__ == "2.1.4"
    assert legacy.sha(engine.match.default_image_path().read_bytes()) == legacy.IMAGE_SHA256
    scratch = engine.match.DEFAULT_MATCH_ROOT / "scratches/creature_update_all"
    config = engine.match.load_scratch_config(scratch)
    assert config.compiler == "msvc6.5" and config.cflags == "/O2 /GB /W3 /GR-"
    before = (HERE / "before.cpp").read_text()
    after = (scratch / "scratch.cpp").read_text()
    assert legacy.sha(before.encode()) == BEFORE_SHA
    assert legacy.sha(after.encode()) == AFTER_SHA
    fixtures.corpse.fixtures.check_layout(config, args.out)
    programs = {name: legacy.build(config, args.out, name, source)
                for name, source in (("before", before), ("after", after))}
    cases = (fixtures.corpse.fixtures.scenarios() + list(fixtures.boundary_cases())
             + list(fixtures.corpse.interaction.boundary_cases()) + list(fixtures.corpse.tiny_cases()))
    assert len(cases) == 3480
    failures = {name: [] for name in programs}
    rows = []
    for index, case in enumerate(cases):
        native = programs["before"].run(True, case)
        row = {"name": case["name"], "native": legacy.observation(native)}
        for name, program in programs.items():
            candidate = program.run(False, case)
            changed = [key for key in legacy.KEYS if native[key] != candidate[key]]
            if changed:
                failures[name].append({"case": case["name"], "differences": {
                    key: legacy.first_difference(native[key], candidate[key]) for key in changed}})
            row[name] = legacy.observation(candidate)
        rows.append(row)
        if index % 400 == 0:
            print(f"Cases {index}/{len(cases)}", flush=True)
    counts = {name: len(rows_) for name, rows_ in failures.items()}
    assert counts == {"before": 0, "after": 0}, failures
    (args.out / "observations.json").write_text(json.dumps(rows, indent=2) + "\n")
    record = {
        "before_source_sha256": BEFORE_SHA,
        "after_source_sha256": AFTER_SHA,
        "metrics": {name: legacy.metric(program) for name, program in programs.items()},
        "cases": len(cases),
        "native_differences": counts,
        "observations_sha256": legacy.sha((args.out / "observations.json").read_bytes()),
        "scope": "Finite native x86 observations with existing callback models; not whole-game equivalence.",
    }
    (HERE / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"PASS: {len(cases)} cases, zero native differences for both sources", flush=True)


if __name__ == "__main__":
    main()
