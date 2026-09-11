"""Isolate the two point-movement frame snapshots against original player_update."""

import argparse
import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("point_fixtures", HERE / "fixtures.py")
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
sys.path.insert(0, str(HERE.parent / "player-aim-direction-2026-09-11"))
v = f.load("aim_verify", "player-aim-direction-2026-09-11", "verify.py")
BASELINE_SHA = "6ec9615d136a330bf87ec2ab7088471124507379b1a6532580eccb31f0476c5e"


def snapshot_source(source):
    for indent in (" " * 24, " " * 16):
        old = (f"{indent}movement_input.x = frame_dt * player->move_dx;\n"
               f"{indent}movement_input.y = frame_dt * player->move_dy;")
        new = (f"{indent}const float movement_dt = frame_dt;\n"
               f"{indent}movement_input.x = movement_dt * player->move_dx;\n"
               f"{indent}movement_input.y = movement_dt * player->move_dy;")
        assert source.count(old) == 1
        source = source.replace(old, new)
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert v.e.unicorn.__version__ == "2.1.4"
    assert v.sha(v.ENGINE.read_bytes()) == v.ENGINE_SHA
    assert v.sha(v.e.match.default_image_path().read_bytes()) == v.IMAGE_SHA
    config = v.e.match.load_scratch_config(v.e.match.DEFAULT_MATCH_ROOT / "scratches/player_update")
    before_source = (HERE / "before.cpp").read_text()
    assert v.sha(before_source.encode()) == BASELINE_SHA
    assert snapshot_source(before_source) == (config.directory / config.source).read_text()
    layout = v.check_layout(config, args.out)
    before_dir = args.out / "before"
    before_dir.mkdir(exist_ok=True)
    (before_dir / config.source).write_text(before_source)
    before = v.e.Program(replace(config, directory=before_dir))
    current = v.e.Program(config)
    cases = list(f.scenarios())
    assert len(cases) == len({r["name"] for r in cases}) == 3827
    (args.out / "cases.json").write_bytes(v.encoded(cases))
    results = []
    coverage = [set(), set(), set()]
    prior = json.loads((HERE.parent / "player-aim-direction-2026-09-11/results.json").read_text())
    for i, case in enumerate(cases):
        native = v.run(current, True, case["frame"])
        old = v.run(before, False, case["frame"])
        candidate = v.run(current, False, case["frame"])
        expected = v.observation(native)
        if expected != v.observation(old) or expected != v.observation(candidate):
            (args.out / "failure.json").write_bytes(v.encoded({"case": case, "native": native, "before": old, "current": candidate}))
            raise AssertionError(case["name"])
        digest = v.sha(v.encoded(expected))
        if i < 3738:
            assert case["name"] == prior["results"][i]["case"]
            assert digest == prior["results"][i]["native_observation_sha256"]
        results.append({"case": case["name"], "equal_observation_sha256": digest})
        for seen, result in zip(coverage, (native, old, candidate), strict=True):
            seen.update(result["coverage"])
        if (i + 1) % 250 == 0:
            print(i + 1, "agree", flush=True)
    native_lines = current.result.target_disassembly
    missing = [{"offset": row.offset, "text": row.text} for row in native_lines if row.offset not in coverage[0]]
    assert len(coverage[0]) == 4198 and len(missing) == 8
    output = {
        "image_sha256": v.IMAGE_SHA, "engine_sha256": v.ENGINE_SHA,
        "runner_sha256": v.sha((HERE.parent / "player-aim-direction-2026-09-11/runner.py").read_bytes()),
        "fixtures_sha256": v.sha((HERE / "fixtures.py").read_bytes()),
        "cases_sha256": v.sha(v.encoded(cases)), "layout": layout,
        "before": v.metrics(before), "current": v.metrics(current),
        "coverage": {name: {"count": len(offsets), "offsets": sorted(offsets)}
                     for name, offsets in zip(("native", "before", "current"), coverage, strict=True)},
        "missing_native": missing, "results": results,
    }
    (args.out / "results.json").write_bytes(v.encoded(output))
    print(json.dumps({"cases": len(results), "mismatches": 0, "native_coverage": len(coverage[0]), "missing_native": missing}))


if __name__ == "__main__":
    main()
