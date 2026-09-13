"""Rebuild player ring/receiver controls and check the bounded native evidence."""

import argparse
import copy
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from crimson import match, match_c2

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "fire_cough_proof", HERE.parent / "player-fire-cough-2026-09-14/verify.py",
)
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)
compile_control, encoded, execute, reconstruct, sha = (
    shared.compile_control,
    shared.encoded,
    shared.execute,
    shared.reconstruct,
    shared.sha,
)

ROOT = match.REPO_ROOT


def region_check(native, candidate, native_rows, candidate_rows, relocs):
    """Compare positional operands before masking only three COFF relocations."""
    assert len(native) == len(candidate) == 68
    assert len(native_rows) == len(candidate_rows) == 24
    assert [r.offset - 0x61A for r in native_rows] == [r.offset - 0x613 for r in candidate_rows]
    expected = [(1, 6), (42, 6), (51, 20)]
    assert [(r.offset - 0x613, r.relocation_type) for r in relocs] == expected
    assert all(r.addend == 0 and r.local_target_offset is None for r in relocs)
    masked_native, masked_candidate = bytearray(native), bytearray(candidate)
    references, branches = [], []
    for a, b in zip(native_rows, candidate_rows, strict=True):
        assert a.size == b.size
        assert match._masked_reference_status(a.masked_references, b.masked_references) == "ok"
        if a.text.startswith("j"):
            aa, bb = re.fullmatch(r"(j\w+) L([0-9a-f]+)", a.text), re.fullmatch(r"(j\w+) L([0-9a-f]+)", b.text)
            assert aa and bb and aa[1] == bb[1]
            dest = int(aa[2], 16) - 0x61A
            assert dest == int(bb[2], 16) - 0x613
            assert dest in {r.offset - 0x61A for r in native_rows}
            branches.append({"offset": a.offset - 0x61A, "target": dest})
        else:
            assert a.text == b.text
        local = [r for r in relocs if b.offset <= r.offset < b.offset + b.size]
        assert len(local) == len(a.masked_references)
        for reloc, ar, br in zip(local, a.masked_references, b.masked_references, strict=True):
            offset = reloc.offset - 0x613
            assert offset + 4 <= b.offset - 0x613 + b.size
            assert ar.explained and br.explained and ar.operand_index == br.operand_index and ar.kind == br.kind
            keys = sorted(set(ar.keys) & set(br.keys))
            assert keys
            references.append({"offset": offset, "keys": keys, "coff_type": reloc.relocation_type})
            masked_native[offset : offset + 4] = b"\0" * 4
            masked_candidate[offset : offset + 4] = b"\0" * 4
    assert masked_native == masked_candidate
    return {
        "bytes": 68,
        "instructions": 24,
        "references": references,
        "branches": branches,
        "native_sha256": sha(native),
        "candidate_sha256": sha(candidate),
        "masked_sha256": sha(masked_native),
    }


def ring(cfg):
    obj = match.compile_scratch(cfg)
    function = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), cfg.symbol)
    result = match.run_match(
        obj_path=obj, function=cfg.function, symbol_name=cfg.symbol, reference_aliases=cfg.reference_aliases,
    )
    image = match.load_image(match.default_image_path())
    native = image.mapped[0x413CCA - image.image_base : 0x413D0E - image.image_base]
    candidate = function.data[0x613:0x657]
    a = [r for r in result.target_disassembly if 0x413CCA <= r.address < 0x413D0E]
    b = [r for r in result.candidate_disassembly if 0x613 <= r.offset < 0x657]
    relocs = [r for r in function.relocation_references if 0x613 <= r.offset < 0x657]
    report = region_check(native, candidate, a, b, relocs)
    # The surrounding full function has already been propagated by frame_map.py.
    na = json.loads((cfg.directory / "native-depths.json").read_text())
    ca = json.loads((cfg.directory / "candidate-depths.json").read_text())
    depths = [
        [na[str(result.target_disassembly.index(x))], ca[str(result.candidate_disassembly.index(y))]]
        for x, y in zip(a, b, strict=True)
    ]
    assert all(x == y for x, y in depths) and depths[0] == [88, 88]
    report["entry_esp_depth"] = 88
    report["all_positional_esp_depths_equal"] = True
    rejected = []
    for name, offset in [("parity-mask", 25), ("odd-projectile-type", 30), ("branch-displacement", 28)]:
        bad = bytearray(candidate)
        bad[offset] ^= 1
        try:
            region_check(native, bytes(bad), a, b, relocs)
        except AssertionError:
            rejected.append(name)
        else:
            raise AssertionError(name)
    bad = copy.deepcopy(b)
    from dataclasses import replace

    call = next(i for i, r in enumerate(bad) if r.text == "call ADDR")
    bad[call] = replace(bad[call], masked_references=(replace(bad[call].masked_references[0], keys=("name:wrong",)),))
    try:
        region_check(native, candidate, a, bad, relocs)
    except AssertionError:
        rejected.append("wrong-call-reference")
    else:
        raise AssertionError("wrong-call-reference")
    report["negative_controls_rejected"] = rejected
    return report


def trace_proof(base_path, shift_path, data):
    paths = [base_path, shift_path]
    snapshots = [match_c2.read_verified(path) for path in paths]
    manifests = [json.loads((path / "manifest.json").read_text()) for path in paths]
    expected = [data["baseline"], next(c["observed"] for c in data["controls"] if c["name"] == "line-shift")]
    anchors, ordering = [], []
    for path, events, manifest, observed in zip(paths, snapshots, manifests, expected, strict=True):
        source = (path / "source/scratch.cpp").read_text()
        assert sha(source.encode()) == observed["source_sha256"] == manifest["source_sha256"]
        obj = path / manifest["object_paths"][0]
        body = match.extract_object_function(match.parse_coff_object(obj.read_bytes()), "player_update")
        assert sha(body.data) == observed["body_sha256"]
        lines = source.splitlines()
        definition = lines.index('extern "C" void player_update(void)') + 1
        angle = lines.index("            float shot_heading = atan2f(shot_delta[1], shot_delta[0]) - 1.5707964f;") + 1
        assert angle - definition == 171
        anchors.append({"definition_file_line": definition, "angle_file_line": angle, "angle_c2_line": 171})
        phases = []
        for phase in [0, 1]:
            event = next(e for e in events if e["function_ordinal"] == 0 and e["phase"] == phase)
            found = []
            for line, op in [(171, 0x190), (173, 0x16D), (174, 0x16D)]:
                # This label also contains pointer addition at phase 0. Pin the
                # observed floating-node flag instead of selecting that address node.
                indices = [
                    i for i, n in enumerate(event["nodes"])
                    if n["line"] == line and n["op"] == op and n["flags"] & 0x40000000
                ]
                assert len(indices) == 1
                found.append(indices[0])
            assert (found[0] < found[1] < found[2]) if phase == 0 else (found[1] < found[2] < found[0])
            phases.append(
                {
                    "phase": phase,
                    "target_rva": event["target_rva"],
                    "boundary": event["boundary"],
                    "angle_index": found[0],
                    "position_y_index": found[1],
                    "position_x_index": found[2],
                },
            )
        ordering.append(phases)
    assert anchors[1]["definition_file_line"] - anchors[0]["definition_file_line"] == 7
    assert ordering[0] == ordering[1]
    comparison = match_c2.compare(*snapshots)
    assert comparison["first_shape_difference"] is None
    assert [[(n["line"], n["op"]) for n in e["nodes"]] for e in snapshots[0]] == [
        [(n["line"], n["op"]) for n in e["nodes"]] for e in snapshots[1]
    ]
    return {"anchors": anchors, "ordering": ordering[0], "comparison": comparison, "manifests": manifests}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--all-controls", action="store_true")
    parser.add_argument("--controls-only", action="store_true")
    parser.add_argument("--trace", action="store_true", help="Repeat preserving baseline and source-shift traces")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    data = json.loads((HERE / "controls.json").read_text())
    for name, digest in {**data["build"]["dependencies"], **data["fixture_dependencies"]}.items():
        assert sha((ROOT / name).read_bytes()) == digest, name
    git = shutil.which("git")
    assert git is not None
    source = subprocess.check_output(
        [git, "show", f"{data['baseline_commit']}:tools/match/scratches/player_update/scratch.cpp"], cwd=ROOT,
    ).decode()
    assert sha(source.encode()) == data["baseline_source_sha256"]
    baseline, row = compile_control(
        source, data["baseline_config"], args.out / "baseline", data["baseline"], data["build"],
    )
    configs, rows = {"baseline": baseline}, [row]
    for c in data["controls"]:
        if args.all_controls or c["name"] == data["selected"] or (args.trace and c["name"] == "line-shift"):
            cfg, row = compile_control(
                reconstruct(source, c), c["config"], args.out / c["name"], c["observed"], data["build"],
            )
            configs[c["name"]] = cfg
            rows.append(row)
            print(json.dumps(row), flush=True)
    selected = configs[data["selected"]]
    assert (selected.directory / selected.source).read_bytes() == (
        match.DEFAULT_MATCH_ROOT / "scratches/player_update/scratch.cpp"
    ).read_bytes()
    frames = {}
    for cfg in [baseline, selected]:
        subprocess.run(
            [sys.executable, str(HERE.parent / "player-frame-controls-2026-09-14/frame_map.py"), str(cfg.directory)],
            check=True,
        )
        frames[cfg.directory.name] = json.loads((cfg.directory / "frame-summary.json").read_text())
    report = {
        "controls_sha256": sha((HERE / "controls.json").read_bytes()),
        "verifier_sha256": sha(Path(__file__).read_bytes()),
        "compiler_controls": rows,
        "frames": frames,
        "ring": ring(selected),
    }
    if not args.controls_only:
        report["execution"] = execute(baseline, selected, args.out)
        assert report["execution"] == json.loads((HERE / "execution.json").read_text())["execution"]
    if args.trace:
        paths = [args.out / "trace-base", args.out / "trace-shift"]
        for name, path in zip(["baseline", "line-shift"], paths, strict=True):
            match_c2.trace(configs[name].directory, path, passes_only=True)
        report["trace"] = trace_proof(*paths, data)
    (args.out / "results.json").write_bytes(encoded(report))


if __name__ == "__main__":
    main()
