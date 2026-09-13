"""Replay all 2928 native spawn cases and ordered writes using Unicorn 2.1.4."""

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

import unicorn
from recover import HERE, recover, sha

from crimson import match

PREVIOUS = HERE.parent / "spawn-grid-dispatch-2026-09-11"
sys.path.insert(0, str(PREVIOUS))
from execute import ENGINE_PATH, Comparison
from fixtures import check_layout, scenarios

KEYS = ("state", "slots", "scalars", "result", "calls", "rng_state", "rng_draws", "writes")
IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"


def serialize(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=lambda item: item.hex()).encode()


def build(config, out, name, source):
    directory = out / name
    directory.mkdir(exist_ok=True)
    (directory / "scratch.cpp").write_text(source)
    return Comparison(replace(config, directory=directory))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/creature_spawn_template")
    layout = check_layout(config, args.out)
    source = recover()
    current = build(config, args.out, "exact", source)
    assert current.program.result.exact and current.program.result.body_byte_exact
    cases = scenarios()
    (args.out / "cases.json").write_bytes(serialize(cases))
    rows, coverage = [], set()
    for index, case in enumerate(cases):
        native, candidate = current.run(True, case), current.run(False, case)
        differences = [key for key in KEYS if native[key] != candidate[key]]
        assert not differences, (case, differences)
        rows.append({"case": index, "native": sha(serialize({k: native[k] for k in KEYS})), "candidate": sha(serialize({k: candidate[k] for k in KEYS}))})
        coverage.update(native["coverage_offsets"])
        if index % 200 == 0:
            print(f"{index + 1}/{len(cases)} native cases PASS", flush=True)
    assert len(rows) == 2928
    controls = []
    case = {"template": 0x18, "heading": 0.75, "seed": 0xBEEF}
    native = current.run(True, case)
    for name, old, new in (("wrong-stride", "ring_member_idx += 0x40", "ring_member_idx += 0x10"), ("missing-row", "ring_member_idx <= 0x100", "ring_member_idx <= 0xc0")):
        assert source.count(old) == 1
        wrong_source = source.replace(old, new)
        wrong = build(config, args.out, name, wrong_source).run(False, case)
        detected = [key for key in KEYS if native[key] != wrong[key]]
        assert "state" in detected and "rng_draws" in detected and "writes" in detected
        controls.append({"name": name, "source_sha256": sha(wrong_source.encode()), "case": case, "detected": detected})
    p = current.program
    manifest = match.load_function_manifest(scope="all")
    receipt = {
        "schema_version": 1, "function": config.function, "unicorn": unicorn.__version__,
        "image_sha256": IMAGE_SHA, "source_sha256": sha(source.encode()),
        "object_sha256": sha(p.object_path.read_bytes()), "body_sha256": sha(p.body.data),
        "native_body_sha256": sha(p.image.function_bytes(p.native_start, p.native_end)),
        "compiler": config.compiler, "cflags": config.cflags, "layout": layout,
        "compiler_files_sha256": {name: sha((match.DEFAULT_MATCH_ROOT / "compilers" / config.compiler / "Bin" / name).read_bytes()) for name in ("CL.EXE", "C1.DLL", "C1XX.DLL", "C2.DLL")},
        "helper_sha256": {name: sha(p.image.function_bytes(*match.resolve_function(manifest, name)[1:])) for name in current.helpers},
        "harness_sha256": {str(path.relative_to(HERE.parent)): sha(path.read_bytes()) for path in (HERE / "replay.py", HERE / "recover.py", PREVIOUS / "execute.py", PREVIOUS / "fixtures.py", ENGINE_PATH)},
        "cases": len(rows), "cases_sha256": sha((args.out / "cases.json").read_bytes()),
        "compared_fields": KEYS, "differences": {}, "rows_sha256": sha(serialize(rows)),
        "native_instruction_coverage": {"covered": len(coverage), "total": len(p.result.target_disassembly), "uncovered": sorted({i.offset for i in p.result.target_disassembly} - coverage)},
        "negative_controls": controls,
        "scope": "Original native caller and allocation helpers; deterministic RNG and recorded callback boundaries from the prior spawn package. Includes PC24 and PC64, all template families, difficulty, retry and overflow cases. Finite execution proof, not arbitrary-input or rendered-game equivalence.",
    }
    (args.out / "rows.json").write_bytes(serialize(rows))
    (args.out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("PASS 2928 cases including ordered writes and two corruption controls", flush=True)


if __name__ == "__main__":
    main()
