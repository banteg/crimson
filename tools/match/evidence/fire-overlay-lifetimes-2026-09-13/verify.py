"""Check Fire overlay arithmetic, source-copy controls, and native gate ownership."""

import argparse
import concurrent.futures
import importlib.util
import json
import random
import struct
from dataclasses import asdict, replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
PREVIOUS = HERE.parent / "renderer-house-style-2026-09-13"
EXECUTOR = HERE.parent / "conventional-corner-rounding-2026-09-11/execute.py"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


e = module("fire_executor", EXECUTOR)
reconstruction = module("source_reconstruction", PREVIOUS / "verify_controls.py")
# Type 45 is admitted only for inactive slot 95, never an active beam record.
e.TYPES = (*e.TYPES, 45)


def digest(value):
    return e.sha(json.dumps(value, sort_keys=True).encode())


def witnesses():
    cases = [
        row["case"]
        for name in ("fire-current.json", "fire-vector-control.json")
        for row in json.loads((PREVIOUS / name).read_text())["failures"]
    ]
    assert len(cases) == 13
    return cases + [dict(case, fpcw=0x007F) for case in cases]


def record(index, position, *, type_id=1, active=1, life=None):
    return {
        "index": index,
        "type_id": type_id,
        "active": active,
        "position": position,
        "origin": [0.0, 0.0],
        "velocity": [1.0, 2.0],
        "angle": e.f32(0.3 + index * 0.01),
        "life": e.f32(0.4) if life is None else life,
    }


def matrix():
    rng = random.Random(0x4253BB)
    cases = []
    for _ in range(256):
        position = [e.f32(rng.uniform(-512, 512)) for _ in range(2)]
        camera = [e.f32(rng.uniform(-512, 512)) for _ in range(2)]
        for cw in (0x007F, 0x037F):
            current = record(3, position)
            current["angle"] = e.f32(0.3)
            owner = record(95, [0.0, 0.0], type_id=45, active=0, life=0.0)
            owner["angle"] = 0.0
            owner["velocity"] = [0.0, 0.0]
            cases.append({"records": [current, owner], "camera": camera, "fpcw": cw, "alpha": e.f32(0.7), "glow": 0})

    adjacent = [struct.unpack("<f", struct.pack("<I", e.bits(0.4) + delta))[0] for delta in (-1, 1)]
    for scenario in range(8):
        seed = witnesses()[scenario]
        position = seed["records"][0]["position"]
        rows = [
            record(0, position),
            record(31, [-11.5, 62.25], type_id=29, active=2),
            record(94, [81.75, -3.0], type_id=5),
        ]
        owner_type = 45
        if scenario == 1:
            owner_type = 1
        elif scenario == 2:
            owner_type = 0
        elif scenario == 3:
            rows = [dict(row, active=0) for row in rows]
        elif scenario == 4:
            rows = [dict(rows[0], life=adjacent[0]), dict(rows[1], life=adjacent[1]), dict(rows[2], life=0.0)]
        elif scenario == 5:
            rows[0]["type_id"] = 0  # The preceding conventional pass deactivates this record.
        elif scenario == 6:
            rows = [dict(rows[2], active=2, type_id=3)]
        elif scenario == 7:
            rows = []
        rows.append(record(95, [21.0, 39.0], type_id=owner_type, active=0))
        for cw in (0x007F, 0x037F):
            for glow in (0, 1):
                for alpha in (0.0, e.f32(0.7), 1.0):
                    cases.append({"records": rows, "camera": seed["camera"], "fpcw": cw, "alpha": alpha, "glow": glow})
    assert len(cases) == 608
    return cases


def overlay_calls(run):
    return [
        (index, args)
        for index, (name, args) in enumerate(run["calls"])
        if name == "grim_draw_quad" and args[2:] == [e.bits(64.0)] * 2
    ]


def oracle(case, native):
    rows = sorted(case["records"], key=lambda row: row["index"])
    owner = next(row for row in rows if row["index"] == 95)
    eligible = [
        row
        for row in rows
        if owner["type_id"] == 45 and row["active"] and row["type_id"] != 0 and e.bits(row["life"]) == e.bits(0.4)
    ]
    expected = []
    for row in eligible:
        x = case["camera"][0] + row["position"][0]
        if case["fpcw"] == 0x007F:
            x = e.f32(x)
        y = e.f32(case["camera"][1] + row["position"][1])
        expected.append([e.bits(x - 32.0), e.bits(y - 32.0), e.bits(64.0), e.bits(64.0)])
    observed = overlay_calls(native)
    assert [args for _, args in observed] == expected
    for row, (index, _) in zip(eligible, observed, strict=True):
        assert native["calls"][index - 1] == ["grim_set_rotation", [e.bits(row["angle"])]]
    return expected


def compare(program, case, native=None):
    assert all(row["type_id"] != 45 or (row["index"] == 95 and row["active"] == 0) for row in case["records"])
    if native is None:
        native = e.run(program, True, case)
    candidate = e.run(program, False, case)
    assert native["pools"] == candidate["pools"] and native["writes"] == candidate["writes"]
    return native, candidate


def window(program):
    """A diagnostic mapping of one window; it cannot award native exact credit."""
    native = [ins for ins in program.result.target_disassembly if 0x277B <= ins.offset < 0x27D1]
    candidate = [ins for ins in program.result.candidate_disassembly if 0x26B0 <= ins.offset < 0x2706]
    assert len(native) == len(candidate) == 19
    mapping = {
        "[esi+0x8]": "[esi+-0x1c]",
        "[esi+0xc]": "[esi+-0x18]",
        "[esp+0xc0]": "[esp+0xd0]",
        "[esp+0x34]": "[esp+0x4c]",
        "[esp+0x38]": "[esp+0x50]",
    }

    def check(left, right, replacements):
        text = left.text
        for before, after in replacements.items():
            text = text.replace(before, after)
        assert text == right.text and left.size == right.size
        assert len(left.masked_references) == len(right.masked_references)
        for a, b in zip(left.masked_references, right.masked_references, strict=True):
            assert a.explained and b.explained and a.operand_index == b.operand_index
            assert set(a.keys) & set(b.keys)

    for left, right in zip(native, candidate, strict=True):
        check(left, left, {})  # The mapping checker must pass its native self-control.
        check(left, right, mapping)
    wrong = replace(
        candidate[9],
        masked_references=(replace(candidate[9].masked_references[0], keys=("bytes4:0000f841",)),),
    )
    try:
        check(native[9], wrong, mapping)
    except AssertionError:
        pass
    else:
        raise AssertionError("window checker accepted a wrong 31.0 subtraction constant")
    return {
        "native_start": "0x004253eb",
        "native_end_exclusive": "0x00425441",
        "candidate_start_offset": "0x26b0",
        "instructions": 19,
        "bytes": sum(ins.size for ins in native),
        "mapping": mapping,
        "native_self_control": "passed",
        "wrong_constant_control": "rejected",
        "rows": [{"native": asdict(a), "candidate": asdict(b)} for a, b in zip(native, candidate, strict=True)],
        "scope": "Instruction schedule with five clean reference pairs and explicit cursor/stack substitutions. No whole-function or encoded-byte exact credit.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=3)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    controls = json.loads((HERE / "source-controls.json").read_text())
    before = (HERE / "before.cpp").read_text()
    assert e.sha(before.encode()) == controls["baseline_sha256"]
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
    assert config.compiler == controls["compiler"] and config.cflags == controls["cflags"]
    assert json.loads(json.dumps(config.reference_aliases)) == controls["reference_aliases"]
    pinned = json.loads((PREVIOUS / "fire-current.json").read_text())
    assert e.sha(match.default_image_path().read_bytes()) == pinned["image_sha256"]
    selected = {"arguments/baseline-inner", "arguments/old-vector-loop", "prior/expression"}

    def check(control):
        source = reconstruction.reconstruct(before, control)
        directory = args.out / control["name"]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / config.source).write_text(source)
        program = e.Program(replace(config, directory=directory))
        failures = []
        for index, case in enumerate(witnesses()):
            native, candidate = compare(program, case)
            oracle(case, native)
            if native["calls"] != candidate["calls"]:
                failures.append(index)
        result = program.result
        assert not result.exact and not result.body_byte_exact
        observed = {
            "ratio": result.ratio,
            "ins": len(result.candidate_lines),
            "refs": result.masked_operand_audit.ok_count,
            "problems": result.masked_operand_audit.problem_count,
            "failed": failures,
            "cases": 26,
        }
        assert observed == control["observed"], (control["name"], observed)
        print(f"{control['name']}: {26 - len(failures)}/26 witnesses agree", flush=True)
        receipt = {"name": control["name"], "source_sha256": e.sha(source.encode()), "observed": observed}
        return receipt, program if control["name"] in selected else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        checked = list(pool.map(check, controls["controls"]))
    programs = {row["name"]: program for row, program in checked if program is not None}
    positive = programs["prior/expression"]
    assert (
        e.sha(positive.image.function_bytes(positive.native_start, positive.native_end)) == pinned["native_body_sha256"]
    )
    native_rows, failures = [], {name: [] for name in selected}
    for index, case in enumerate(matrix()):
        native = e.run(positive, True, case)
        expected = oracle(case, native)
        native_rows.append(
            {
                "index": index,
                "case": case,
                "overlay": expected,
                "native_trace_sha256": digest(native["calls"]),
                "pools": native["pools"],
                "writes": native["writes"],
            },
        )
        for name, program in programs.items():
            _, candidate = compare(program, case, native)
            if native["calls"] != candidate["calls"]:
                differences = [
                    (i, a, b)
                    for i, (a, b) in enumerate(zip(native["calls"], candidate["calls"], strict=True))
                    if a != b
                ]
                failures[name].append({"index": index, "differences": differences})
    assert not failures["prior/expression"]
    for name, receipt in (
        ("arguments/baseline-inner", "fire-current.json"),
        ("arguments/old-vector-loop", "fire-vector-control.json"),
    ):
        expected = json.loads((PREVIOUS / receipt).read_text())["failures"]
        assert [row["index"] for row in failures[name] if row["index"] < 512] == [row["index"] for row in expected]
    fixtures = "".join(json.dumps(row, sort_keys=True) + "\n" for row in native_rows)
    if (HERE / "fixtures.jsonl").exists():
        assert fixtures == (HERE / "fixtures.jsonl").read_text()
    (args.out / "fixtures.jsonl").write_text(fixtures)
    listings = []
    for name, program in programs.items():
        result = match.generate_compiler_listing(program.config, output=program.config.directory / "listing.cod")
        payload = match.compiler_listing_payload(result)
        listings.append(
            {
                key: value
                for key, value in payload.items()
                if key not in {"listing", "metadata", "scratch", "canonical_object"}
            },
        )
        listings[-1]["name"] = name
    receipt = {
        "verifier_sha256": e.sha(Path(__file__).read_bytes()),
        "executor_sha256": e.sha(EXECUTOR.read_bytes()),
        "engine_sha256": e.sha(e.ENGINE.read_bytes()),
        "reconstruction_sha256": e.sha((PREVIOUS / "verify_controls.py").read_bytes()),
        "controls_sha256": e.sha((HERE / "source-controls.json").read_bytes()),
        "image_sha256": pinned["image_sha256"],
        "native_body_sha256": pinned["native_body_sha256"],
        "unicorn_version": e.unicorn.__version__,
        "controls": [row for row, _ in checked],
        "fixtures": {"count": len(native_rows), "sha256": e.sha(fixtures.encode())},
        "failures": failures,
        "window": window(positive),
        "listings": listings,
        "scope": "Finite PC24/PC64 input oracles, full ordered caller traces and pool/write state with existing external-call models. No GPU or all-input proof; canonical scratch unchanged.",
    }
    (args.out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        json.dumps({"cases": len(native_rows), "failures": {name: len(rows) for name, rows in failures.items()}}),
        flush=True,
    )


if __name__ == "__main__":
    main()
