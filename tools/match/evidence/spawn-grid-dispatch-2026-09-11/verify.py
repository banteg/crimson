"""Replay spawn dispatch recovery and native grid witnesses with Unicorn 2.1.4.

Requires local JIT permission. Recording callbacks bound the result; write-order
and remaining static reference differences are measured, not waived as exact.
"""

import argparse
import hashlib
import json
from collections import Counter
from dataclasses import replace
from pathlib import Path

import unicorn
from execute import ENGINE_PATH, Comparison, match
from fixtures import check_layout, creature, scenarios
from recover import recover

HERE = Path(__file__).resolve().parent
BEFORE_SHA256 = "5c1fdd779bb8b027eca91c28d9d113a7cbaf6b965a85a542f8b161b8d0c3305f"
IMAGE_SHA256 = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
KEYS = ("state", "slots", "scalars", "result", "calls", "rng_state", "rng_draws")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def serialize(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=lambda item: item.hex()).encode()


def observation(value):
    return sha(serialize({key: value[key] for key in KEYS}))


def build(config, out, name, source):
    directory = out / name
    directory.mkdir(exist_ok=True)
    (directory / "scratch.cpp").write_text(source)
    return Comparison(replace(config, directory=directory))


def metric(comparison):
    p = comparison.program
    r = p.result
    return {
        "ratio": r.ratio,
        "native_instructions": len(r.target_disassembly),
        "candidate_instructions": len(r.candidate_disassembly),
        "normalized_exact": r.exact,
        "body_byte_exact": r.body_byte_exact,
        "references": [
            r.masked_operand_audit.ok_count,
            r.masked_operand_audit.unresolved_count,
            r.masked_operand_audit.mismatch_count,
        ],
        "object_sha256": sha(p.object_path.read_bytes()),
        "body_sha256": sha(p.body.data),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--candidate-source", type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA256
    before = (HERE / "before.cpp").read_text()
    assert sha(before.encode()) == BEFORE_SHA256
    recovered = recover(before)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/creature_spawn_template")
    candidate_path = args.candidate_source or config.directory / config.source
    assert candidate_path.read_text() == recovered
    layout = check_layout(config, out)
    old_program = build(config, out, "before", before)
    current_program = build(config, out, "recovered", recovered)
    cases = scenarios()
    (out / "cases.json").write_text(json.dumps(cases, indent=2) + "\n")
    rows, witnesses, grids = [], [], []
    before_differences, remaining_differences = Counter(), Counter()
    native_coverage, current_coverage = set(), set()
    for index, case in enumerate(cases):
        native = current_program.run(True, case)
        current = current_program.run(False, case)
        old = old_program.run(False, case)
        differences = [key for key in KEYS if native[key] != current[key]]
        if differences:
            (out / "failure.json").write_bytes(
                serialize({"case": case, "differences": differences, "native": native, "candidate": current}),
            )
            raise AssertionError(f"Mismatch in {case['name']}: {differences}")
        changed = [key for key in KEYS if native[key] != old[key]]
        before_differences.update(changed)
        if native["writes"] != current["writes"]:
            remaining_differences["writes"] += 1
        if changed and len(witnesses) < 12:
            tail = (native["result"] - current_program.program.address("creature_pool")) // 152
            assert 0 <= tail <= 384
            witnesses.append(
                {
                    "case": index,
                    "differences": changed,
                    "native_tail": creature(native["state"], tail),
                    "before_tail": creature(old["state"], tail),
                    "native_calls": native["calls"],
                    "before_calls": old["calls"],
                },
            )
        rows.append(
            {
                "case": index,
                "native": observation(native),
                "before": observation(old),
                "recovered": observation(current),
                "before_differences": changed,
                "native_writes": sha(serialize(native["writes"])),
                "recovered_writes": sha(serialize(current["writes"])),
            },
        )
        native_coverage.update(native["coverage_offsets"])
        current_coverage.update(current["coverage_offsets"])
        if 0x14 <= case["template"] <= 0x18 and case.get("occupied", 0) == 0 and case.get("rng", "lcg") == "lcg":
            active = [creature(native["state"], slot) for slot in range(384) if native["state"][slot * 152]]
            assert len(active) == 28
            assert native["rng_draws"] == 29 + int(case.get("heading", -100) == -100)
            assert len([call for call in native["calls"] if call[0] == "creature_alloc_slot"]) == 28
            for child, (x, y) in zip(
                active[1:],
                ((x, y) for x in range(0, -513, -64) for y in (128, 192, 256)),
                strict=True,
            ):
                assert (child["target_offset_x"], child["target_offset_y"]) == (x, y)
            grids.append(
                {
                    "case": index,
                    "input": case,
                    "creatures": active,
                    "rng_draws": native["rng_draws"],
                    "rng_state": native["rng_state"],
                    "calls": native["calls"],
                },
            )
        if index % 200 == 0:
            print(f"Verified {index + 1}/{len(cases)} cases", flush=True)
    assert before_differences["state"] and before_differences["calls"]
    assert remaining_differences["writes"]
    controls = []
    control_case = {"template": 0x18, "heading": 0.75, "seed": 0xBEEF}
    native = current_program.run(True, control_case)
    for name, old_text, new_text in (
        ("wrong-row-stride", "grid_vertical_offset + 0x40", "grid_vertical_offset + 0x10"),
        ("omit-last-row", "grid_vertical_offset <= 0x100", "grid_vertical_offset <= 0xc0"),
    ):
        assert recovered.count(old_text) == 1
        wrong_source = recovered.replace(old_text, new_text)
        wrong_program = build(config, out, name, wrong_source)
        wrong = wrong_program.run(False, control_case)
        detected = [key for key in KEYS if native[key] != wrong[key]]
        assert "state" in detected and "rng_draws" in detected
        controls.append(
            {
                "name": name,
                "source_sha256": sha(wrong_source.encode()),
                "case": control_case,
                "detected": detected,
                "native_draws": native["rng_draws"],
                "wrong_draws": wrong["rng_draws"],
            },
        )
    p = current_program.program
    manifest = match.load_function_manifest(scope="all")
    record = {
        "schema_version": 1,
        "function": config.function,
        "unicorn": unicorn.__version__,
        "image_sha256": IMAGE_SHA256,
        "native_body_sha256": sha(p.image.function_bytes(p.native_start, p.native_end)),
        "source_sha256": {"before": sha(before.encode()), "recovered": sha(recovered.encode())},
        "harness_sha256": {
            name: sha((HERE / name).read_bytes()) for name in ("verify.py", "execute.py", "fixtures.py", "recover.py")
        },
        "engine_sha256": sha(ENGINE_PATH.read_bytes()),
        "matcher_sha256": sha(Path(match.__file__).read_bytes()),
        "layout": layout,
        "compiler": config.compiler,
        "cflags": config.cflags,
        "compiler_files_sha256": {
            name: sha((match.DEFAULT_MATCH_ROOT / "compilers" / config.compiler / "Bin" / name).read_bytes())
            for name in ("CL.EXE", "C1.DLL", "C1XX.DLL", "C2.DLL")
        },
        "helper_sha256": {
            name: sha(p.image.function_bytes(*match.resolve_function(manifest, name)[1:]))
            for name in current_program.helpers
        },
        "before": metric(old_program),
        "recovered": metric(current_program),
        "cases": len(cases),
        "cases_sha256": sha((out / "cases.json").read_bytes()),
        "before_differences": dict(before_differences),
        "remaining_differences": dict(remaining_differences),
        "negative_controls": controls,
        "native_instruction_coverage": {
            "covered": len(native_coverage),
            "total": len(p.result.target_disassembly),
            "uncovered": sorted({i.offset for i in p.result.target_disassembly} - native_coverage),
        },
        "candidate_instruction_coverage": {
            "covered": len(current_coverage),
            "total": len(p.result.candidate_disassembly),
            "uncovered": sorted({i.offset for i in p.result.candidate_disassembly} - current_coverage),
        },
        "witnesses": witnesses,
        "grid_witnesses": grids,
        "rows": rows,
    }
    (out / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(
        json.dumps({"cases": len(cases), "before": dict(before_differences), "remaining": dict(remaining_differences)}),
        flush=True,
    )


if __name__ == "__main__":
    main()
