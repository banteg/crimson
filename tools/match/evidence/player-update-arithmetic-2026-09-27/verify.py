"""Reproduce the retained player_update recovery and its bounded native proof."""

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import replace
from pathlib import Path

from regions import verify as verify_regions

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
sys.path.insert(0, str(HERE.parent / "player-aim-direction-2026-09-11"))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v = load("aim_verify", HERE.parent / "player-aim-direction-2026-09-11/verify.py")
fixtures = load("point_fixtures", HERE.parent / "player-point-frame-2026-09-11/fixtures.py")
residual = load("residual_map", ROOT / "scripts/c2/residual_map.py")
BEFORE_SHA = "2e7b41bf5aaf3cd2f9c364496fe97da2c0e727e034afdaef40eae7521c2dd8d8"
AFTER_SHA = "32acad8ac4ebfa7c6af8f1cff460357473135696ed0c91435ba3493973efcd1c"
C2_SHA = "d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a"


def recover(source, *, movement=True, turn=True, smoke=True):
    if movement:
        source, count = re.subn(
            r"(cosf|sinf)\(player->heading - 1\.5707964f\) \* player->move_speed(\n +\* \(3\.1415927f - angle_step\))",
            r"(\1(player->heading - 1.5707964f) * player->move_speed)\2",
            source,
        )
        assert count == 8
    if turn:
        for sign in ("-", "+"):
            old = (
                "                player->turn_speed = player->turn_speed + frame_dt * 10.0f;\n"
                "                player->heading = player->heading\n"
                f"                    {sign} player->turn_speed * frame_dt * 0.5f;"
            )
            new = (
                "                float current_turn_speed = player->turn_speed + frame_dt * 10.0f;\n"
                "                player->turn_speed = current_turn_speed;\n"
                "                player->heading = player->heading\n"
                f"                    {sign} current_turn_speed * frame_dt * 0.5f;"
            )
            assert source.count(old) == 1
            source = source.replace(old, new)
    if smoke:
        assert source.count("float smoke_angle =") == 1
        source = source.replace("float smoke_angle =", "scalar =")
        source = source.replace("cosf(smoke_angle)", "cosf(scalar)").replace("sinf(smoke_angle)", "sinf(scalar)")
    return source


def metrics(program):
    return {**v.metrics(program), "scores": residual.ratios(program.result)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert v.e.unicorn.__version__ == "2.1.4"
    assert v.sha(v.ENGINE.read_bytes()) == v.ENGINE_SHA
    assert v.sha(v.e.match.default_image_path().read_bytes()) == v.IMAGE_SHA
    assert v.sha((ROOT / "tools/match/compilers/msvc6.5/Bin/C2.DLL").read_bytes()) == C2_SHA
    config = v.e.match.load_scratch_config(v.e.match.DEFAULT_MATCH_ROOT / "scratches/player_update")
    before = (HERE / "before.cpp").read_text()
    after = (config.directory / config.source).read_text()
    assert v.sha(before.encode()) == BEFORE_SHA
    assert v.sha(after.encode()) == AFTER_SHA and recover(before) == after
    layout = v.check_layout(config, args.out)
    current = v.e.Program(config)

    def build(name, source):
        directory = args.out / name
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_text(source)
        (directory / "scratch.conf").write_bytes((config.directory / "scratch.conf").read_bytes())
        return v.e.Program(replace(config, directory=directory))

    old = build("before", before)
    ablations = {
        "without_movement_groups": build("without_movement_groups", recover(before, movement=False)),
        "without_turn_temporary": build("without_turn_temporary", recover(before, turn=False)),
        "without_smoke_reuse": build("without_smoke_reuse", recover(before, smoke=False)),
    }
    regions = verify_regions(current, ablations)
    (args.out / "regions.json").write_bytes(v.encoded(regions))
    cases = list(fixtures.scenarios())
    assert len(cases) == len({case["name"] for case in cases}) == 3827
    (args.out / "cases.json").write_bytes(v.encoded(cases))
    programs = {"before": old, "after": current, **ablations}
    differences = {name: [] for name in programs}
    coverage = {name: set() for name in ("native", *programs)}
    rows = []
    for i, case in enumerate(cases):
        native = v.run(current, True, case["frame"])
        expected = v.observation(native)
        coverage["native"].update(native["coverage"])
        hashes = {"native": v.sha(v.encoded(expected))}
        for name, program in programs.items():
            result = v.run(program, False, case["frame"])
            observed = v.observation(result)
            hashes[name] = v.sha(v.encoded(observed))
            coverage[name].update(result["coverage"])
            if observed != expected:
                differences[name].append(case["name"])
                assert name != "after", case["name"]
        rows.append({"case": case["name"], "observation_sha256": hashes})
        if (i + 1) % 500 == 0:
            print(f"{i + 1}/{len(cases)} agree; before differs in {len(differences['before'])}", flush=True)
    assert len(differences["before"]) == 364
    assert differences["without_movement_groups"]
    # A native instruction/storage mismatch need not be a behavior mismatch
    # at PC=24. Report the turn and smoke ablations without inventing a witness.
    result = {
        "schema": 1,
        "precision": "x87 PC=24, round-to-nearest",
        "image_sha256": v.IMAGE_SHA,
        "engine_sha256": v.ENGINE_SHA,
        "c2_sha256": C2_SHA,
        "unicorn_version": v.e.unicorn.__version__,
        "layout": layout,
        "programs": {name: metrics(program) for name, program in programs.items()},
        "cases": len(cases),
        "cases_sha256": v.sha(v.encoded(cases)),
        "mismatch_cases": differences,
        "coverage": {name: {"instructions": len(pcs), "offsets": sorted(pcs)} for name, pcs in coverage.items()},
        "regions_sha256": v.sha(v.encoded(regions)),
        "files": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (
                HERE / "verify.py",
                HERE / "regions.py",
                HERE / "before.cpp",
                HERE.parent / "player-aim-direction-2026-09-11/verify.py",
                HERE.parent / "player-aim-direction-2026-09-11/runner.py",
                HERE.parent / "player-aim-direction-2026-09-11/fixtures.py",
                HERE.parent / "player-aim-direction-2026-09-11/layout.py",
                HERE.parent / "player-point-frame-2026-09-11/fixtures.py",
                HERE.parent / "player-fire-bullets-shortcut-2026-09-11/verify.py",
                ROOT / "scripts/c2/residual_map.py",
            )
        },
        "results": rows,
    }
    (args.out / "results.json").write_bytes(v.encoded(result))
    print(json.dumps({"cases": len(cases), "mismatches": {name: len(cases) for name, cases in differences.items()}}))


if __name__ == "__main__":
    main()
