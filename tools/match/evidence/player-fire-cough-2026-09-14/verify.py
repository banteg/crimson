"""Replay Fire Cough controls and compare the selected source with native at PC=24."""

import argparse
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
ROOT = match.REPO_ROOT


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reconstruct(source, control):
    lines = source.splitlines(keepends=True)
    previous = len(lines)
    for edit in reversed(control["edits"]):
        start, stop = edit["start"], edit["stop"]
        assert 0 <= start <= stop <= previous
        assert "".join(lines[start:stop]) == edit["old"]
        lines[start:stop] = edit["new"].splitlines(keepends=True)
        previous = start
    result = "".join(lines)
    assert sha(result.encode()) == control["observed"]["source_sha256"]
    return result


def compile_control(source, config, directory, expected, build):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "scratch.cpp").write_text(source)
    (directory / "scratch.conf").write_text(config)
    cfg = match.load_scratch_config(directory)
    assert cfg.function == "player_update" and cfg.symbol == "player_update"
    assert cfg.compiler == build["compiler"] and cfg.cflags == build["cflags"]
    obj = match.compile_scratch(cfg, force=True)
    receipt = json.loads((obj.parent / "scratch-build.json").read_text())
    assert receipt["key"]["toolchain"] == build["toolchain"]
    body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
    result = match.run_match(
        obj_path=obj,
        function=cfg.function,
        symbol_name=cfg.symbol,
        reference_aliases=cfg.reference_aliases,
    )
    for label, rows in [("native", result.target_disassembly), ("candidate", result.candidate_disassembly)]:
        (directory / f"{label}.json").write_bytes(encoded([asdict(row) for row in rows]))
    audit = result.masked_operand_audit
    measured = {
        "source_sha256": sha(source.encode()),
        "body_sha256": sha(body.data),
        "exact": result.exact,
        "body_byte_exact": result.body_byte_exact,
        "instructions": len(result.candidate_lines),
        "target": len(result.target_lines),
        "prefix": result.prefix_instructions,
        "refs": [audit.ok_count, audit.unresolved_count, audit.mismatch_count],
        "ratio": result.ratio,
    }
    assert measured == {key: expected[key] for key in measured}, directory.name
    return cfg, {"name": directory.name, **measured}


def execute(before_cfg, after_cfg, output):
    fixture_root = HERE.parent / "player-aim-direction-2026-09-11"
    runner = load("cough_runner", fixture_root / "runner.py")
    sys.modules["runner"] = runner
    fixtures = load("cough_fixtures", HERE.parent / "player-point-frame-2026-09-11/fixtures.py")
    layout = load("cough_layout", fixture_root / "layout.py")
    assert runner.e.unicorn.__version__ == "2.1.4"
    assert (
        sha(match.default_image_path().read_bytes())
        == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    )
    before, after = runner.e.Program(before_cfg), runner.e.Program(after_cfg)
    cases = list(fixtures.scenarios())
    assert len(cases) == len({case["name"] for case in cases}) == 3827
    prior = json.loads((HERE.parent / "player-point-frame-2026-09-11/results.json").read_text())
    coverage = [set(), set(), set()]
    hashes = []
    for i, case in enumerate(cases):
        values = [
            runner.run(before, True, case["frame"]),
            runner.run(before, False, case["frame"]),
            runner.run(after, False, case["frame"]),
        ]
        observations = [{key: value[key] for key in ("state", "calls")} for value in values]
        if not observations[0] == observations[1] == observations[2]:
            (output / "failure.json").write_bytes(encoded({"case": case, "observations": observations}))
            raise AssertionError(case["name"])
        digest = sha(encoded(observations[0]))
        assert prior["results"][i] == {"case": case["name"], "equal_observation_sha256": digest}
        hashes.append({"case": case["name"], "observation_sha256": digest})
        for seen, value in zip(coverage, values, strict=True):
            seen.update(value["coverage"])
        if (i + 1) % 250 == 0:
            print(f"{i + 1}/{len(cases)} native/before/after fixtures agree", flush=True)
    missing = [
        {"offset": row.offset, "text": row.text}
        for row in after.result.target_disassembly
        if row.offset not in coverage[0]
    ]
    assert len(coverage[0]) == 4198 and len(missing) == 8
    return {
        "cases": len(cases),
        "differences": 0,
        "cases_sha256": sha(encoded(cases)),
        "observations_sha256": sha(encoded(hashes)),
        "layout": layout.check_layout(after_cfg, output),
        "coverage": {
            name: {"count": len(seen), "offsets_sha256": sha(encoded(sorted(seen)))}
            for name, seen in zip(("native", "before", "after"), coverage, strict=True)
        },
        "missing_native": missing,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--all-controls", action="store_true", help="Also replay every non-selected compiler control")
    parser.add_argument("--controls-only", action="store_true", help="Skip machine-code fixtures")
    args = parser.parse_args()
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    data = json.loads((HERE / "controls.json").read_text())
    for name, digest in {**data["build"]["dependencies"], **data["fixture_dependencies"]}.items():
        assert sha((ROOT / name).read_bytes()) == digest, name
    git = shutil.which("git")
    assert git is not None
    source = subprocess.check_output(
        [git, "show", f"{data['baseline_commit']}:tools/match/scratches/player_update/scratch.cpp"],
        cwd=ROOT,
    ).decode()
    assert sha(source.encode()) == data["baseline_source_sha256"]
    selected = next(c for c in data["controls"] if c["name"] == data["selected"])
    selected_source = reconstruct(source, selected)
    assert selected_source == (match.DEFAULT_MATCH_ROOT / "scratches/player_update/scratch.cpp").read_text()
    before_cfg, baseline = compile_control(
        source,
        data["baseline_config"],
        output / "baseline",
        data["baseline"],
        data["build"],
    )
    rows = [baseline]
    after_cfg = None
    for control in data["controls"] if args.all_controls else [selected]:
        cfg, measured = compile_control(
            reconstruct(source, control),
            control["config"],
            output / control["name"],
            control["observed"],
            data["build"],
        )
        rows.append(measured)
        if control["name"] == data["selected"]:
            after_cfg = cfg
        print(json.dumps(measured), flush=True)
    assert after_cfg is not None
    frames = {}
    for cfg in (before_cfg, after_cfg):
        subprocess.run(
            [sys.executable, str(HERE.parent / "player-frame-controls-2026-09-14/frame_map.py"), str(cfg.directory)],
            check=True,
        )
        frames[cfg.directory.name] = json.loads((cfg.directory / "frame-summary.json").read_text())
    report = {
        "schema": 1,
        "controls_sha256": sha((HERE / "controls.json").read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "compiler_controls": rows,
        "frames": frames,
    }
    if not args.controls_only:
        report["execution"] = execute(before_cfg, after_cfg, output)
    (output / "results.json").write_bytes(encoded(report))


if __name__ == "__main__":
    main()
