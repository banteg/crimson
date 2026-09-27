"""Verify the isolated plague scheduling change and bounded native call traces."""

import argparse
import importlib.util
import json
import random
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE = Path("tools/match/scratches/projectile_render/scratch.cpp")
BASE = "39f6d6465"
BEFORE_SHA = "1d23261d83fbe1b29a7109f6b6495ff108141c43c395cbe1dad02b4305e9638f"
AFTER_SHA = "00644e8cb56fea99ea14846a7be552ff16ec86547843b136a6593498b84a2cbd"
BEGIN, END = 0x2510, 0x2528
NATIVE = 0x42518C


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


e = module("plague_executor", HERE.parent / "conventional-corner-rounding-2026-09-11/execute.py")
e.TYPES = (*e.TYPES, 0x29)


def region_matches(program, body):
    refs = [r for r in body.relocation_references if BEGIN <= r.offset < END]
    if len(refs) != 1:
        return False
    r = refs[0]
    if (r.offset, r.key, r.addend, r.relocation_type, r.explained) != (
        0x2522,
        "name:camera_offset+0x4",
        4,
        6,
        True,
    ):
        return False
    candidate = bytearray(body.data[BEGIN:END])
    i = r.offset - BEGIN
    candidate[i : i + 4] = (program.address("camera_offset") + 4).to_bytes(4, "little")
    return candidate == program.image.function_bytes(NATIVE, NATIVE + END - BEGIN)


def cases():
    rng = random.Random(0x42518C)
    out = []
    # Both x87 precisions; initial five-quad and fading one-quad paths;
    # zero, noncanonical active bytes, pool endpoints and mixed conventional draws.
    for sample in range(32):
        position = [e.f32(rng.uniform(-512, 512)) for _ in range(2)]
        camera = [e.f32(rng.uniform(-512, 512)) for _ in range(2)]
        for life in (e.f32(0.4), e.f32(0.2), 0.0):
            for cw in (0x007F, 0x037F):
                records = [
                    {
                        "index": (0, 3, 31, 95)[sample % 4],
                        "type_id": 0x29,
                        "active": (1, 2, 0, 1)[sample % 4],
                        "position": position,
                        "origin": [0.0, 0.0],
                        "velocity": [1.0, 2.0],
                        "angle": e.f32(rng.uniform(-6.0, 6.0)),
                        "life": life,
                    },
                ]
                if sample % 2:
                    records.append(dict(records[0], index=62, type_id=1, active=1))
                out.append(
                    {
                        "records": records,
                        "camera": camera,
                        "fpcw": cw,
                        "alpha": e.f32((0.0, 0.7, 1.0)[sample % 3]),
                        "glow": sample % 2,
                    },
                )
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    git = shutil.which("git")
    assert git is not None
    before = subprocess.check_output([git, "show", f"{BASE}:{SOURCE}"], cwd=ROOT)
    after = (ROOT / SOURCE).read_bytes()
    assert e.sha(before) == BEFORE_SHA and e.sha(after) == AFTER_SHA
    config = match.load_scratch_config(ROOT / SOURCE.parent)
    programs = {}
    for name, source in (("before", before), ("after", after)):
        directory = args.out / name
        directory.mkdir()
        (directory / "scratch.cpp").write_bytes(source)
        programs[name] = e.Program(replace(config, directory=directory))
    old, new = programs["before"], programs["after"]
    assert len(old.body.data) == len(new.body.data)
    assert old.body.data[:BEGIN] == new.body.data[:BEGIN]
    assert old.body.data[END:] == new.body.data[END:]
    outside = lambda body: [r for r in body.relocation_references if not BEGIN <= r.offset < END]
    assert outside(old.body) == outside(new.body)
    assert region_matches(new, new.body) and not region_matches(old, old.body)
    wrong_stack = bytearray(new.body.data)
    wrong_stack[0x251F] = 0x18
    assert not region_matches(new, replace(new.body, data=bytes(wrong_stack)))
    wrong_refs = tuple(
        replace(r, key="name:camera_offset") if r.offset == 0x2522 else r for r in new.body.relocation_references
    )
    assert not region_matches(new, replace(new.body, relocation_references=wrong_refs))
    fixtures, hashes, coverage = cases(), [], set()
    for case in fixtures:
        native = e.run(new, True, case)
        for program in (old, new):
            candidate = e.run(program, False, case)
            for key in ("calls", "pools", "writes"):
                assert candidate[key] == native[key]
        coverage.update(native["coverage_offsets"])
        hashes.append(e.sha(json.dumps(native["calls"], sort_keys=True).encode()))
    assert NATIVE - new.native_start in coverage
    assert e.unicorn.__version__ == "2.1.4"
    metric_keys = (
        "exact",
        "body_byte_exact",
        "match_ratio",
        "prefix_instructions",
        "target_instructions",
        "candidate_instructions",
        "references",
        "stack_frame",
    )
    receipt = {
        "source_sha256": AFTER_SHA,
        "before_source_sha256": BEFORE_SHA,
        "image_sha256": e.sha(match.default_image_path().read_bytes()),
        "verifier_sha256": e.sha(Path(__file__).read_bytes()),
        "executor_sha256": e.sha((HERE.parent / "conventional-corner-rounding-2026-09-11/execute.py").read_bytes()),
        "engine_sha256": e.sha(e.ENGINE.read_bytes()),
        "body_sha256": {k: e.sha(p.body.data) for k, p in programs.items()},
        "metrics": {
            k: {key: value for key, value in match.match_result_payload(p.result).items() if key in metric_keys}
            for k, p in programs.items()
        },
        "changed_candidate_extent": [hex(BEGIN), hex(END)],
        "native_extent": [hex(NATIVE), hex(NATIVE + END - BEGIN)],
        "outside_bytes_and_relocations_identical": True,
        "region_byte_exact": True,
        "negative_controls_rejected": ["old-schedule", "wrong-stack-depth", "wrong-relocation"],
        "fixtures": len(fixtures),
        "fixtures_sha256": e.sha(json.dumps(fixtures, sort_keys=True).encode()),
        "ordered_trace_sha256": e.sha(json.dumps(hashes).encode()),
        "unicorn_version": e.unicorn.__version__,
        "scope": "Finite native caller traces with recording external contracts; no GPU or arbitrary-input equivalence claim.",
    }
    (args.out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"24-byte region exact; all outside bytes/references unchanged; {len(fixtures)} native traces agree")


if __name__ == "__main__":
    main()
