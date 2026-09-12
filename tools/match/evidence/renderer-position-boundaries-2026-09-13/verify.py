"""Verify retained position arithmetic and the native post-rotation type reload."""

import argparse
import importlib.util
import json
import random
import struct
from dataclasses import replace
from pathlib import Path

from crimson import match


def module(name, path):
    s = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


HERE = Path(__file__).resolve().parent
FIRE_PROOF = HERE.parent / "fire-overlay-lifetimes-2026-09-13/verify.py"
f = module("fire_proof", FIRE_PROOF)
e = f.e
HALF = {1: 3.0, 4: 4.0, 29: 2.0}


def billboard_cases():
    """Find eight Y-store witnesses for each billboard branch, at both precisions."""
    rng = random.Random(0x425537)
    rows = []
    hits = {t: 0 for t in HALF}
    for _i in range(100000):
        pos = [e.f32(rng.uniform(-512, 512)) for _ in range(2)]
        cam = [e.f32(rng.uniform(-512, 512)) for _ in range(2)]
        for t, h in HALF.items():
            if hits[t] >= 8 or e.bits(cam[1] + pos[1] - h) == e.bits(e.f32(cam[1] + pos[1]) - h):
                continue
            hits[t] += 1
            for cw in (0x007F, 0x037F):
                record = f.record(3, pos, type_id=t)
                owner = f.record(95, [0.0, 0.0], type_id=1, active=0)
                rows.append({"records": [record, owner], "camera": cam, "alpha": e.f32(0.7), "glow": 0, "fpcw": cw})
        if all(n == 8 for n in hits.values()):
            break
    assert len(rows) == 48, hits
    return rows


def quad_oracle(case, run, draw_type=None):
    # Splitter also draws an earlier 20px quad; select the native billboard callsite.
    row = case["records"][0]
    half = HALF[draw_type if draw_type is not None else row["type_id"]]
    x = case["camera"][0] + row["position"][0]
    if case["fpcw"] == 0x007F:
        x = e.f32(x)
    y = e.f32(case["camera"][1] + row["position"][1])
    expected = [e.bits(x - half), e.bits(y - half), e.bits(2 * half), e.bits(2 * half)]
    quads = [
        a
        for (n, a), ret in zip(run["calls"], run["return_sites"], strict=True)
        if n == "grim_draw_quad" and ret == 0x42563B
    ]
    assert quads == [expected], (case, quads, expected)
    return expected


def callback_run(program, native, case, new_type):
    """Temporarily change type in the rotation stub, restoring it after the draw.

    This models an external-call boundary, not an observed behavior of Grim.
    The original code hook still records calls and enforces machine invariants.
    Uc is a factory (it dispatches to UcIntel), so wrap its returned instance.
    These callback controls run serially because the factory override is global.
    """
    original = e.unicorn.Uc
    plain = e.run(program, native, case)
    reference = e.run(program, True, case)
    call_index = reference["return_sites"].index(0x42552F)
    assert reference["calls"][call_index][0] == "grim_set_rotation"
    ordinal = sum(n == "grim_set_rotation" for n, _ in reference["calls"][: call_index + 1])
    expected_return = plain["return_sites"][call_index]
    address = program.address("projectile_pool") + 3 * 0x40 + 32
    rotation = e.STUB + (0xFC // 4) * 16
    draw = e.STUB + (0x11C // 4) * 16
    events = []

    def Uc(*ctor_args, **ctor_kwargs):
        instance = original(*ctor_args, **ctor_kwargs)
        original_hook_add = instance.hook_add

        def hook_add(hook_type, callback, *args, **kwargs):
            if hook_type == e.unicorn.UC_HOOK_CODE:
                count = 0
                old = None

                def wrapped(uc, pc, size, data):
                    nonlocal count, old
                    callback(uc, pc, size, data)
                    if pc == rotation:
                        count += 1
                        if count == ordinal:
                            esp = uc.reg_read(e.x86.UC_X86_REG_ESP)
                            ret = struct.unpack("<I", uc.mem_read(esp, 4))[0]
                            assert ret == expected_return
                            old = bytes(uc.mem_read(address, 4))
                            uc.mem_write(address, struct.pack("<I", new_type))
                            events.append(["rotation-type-change", struct.unpack("<I", old)[0], new_type])
                    elif pc == draw and old is not None:
                        uc.mem_write(address, old)
                        old = None
                        events.append(["restore-after-draw"])

                return original_hook_add(hook_type, wrapped, *args, **kwargs)
            return original_hook_add(hook_type, callback, *args, **kwargs)

        instance.hook_add = hook_add
        return instance

    e.unicorn.Uc = Uc
    try:
        result = e.run(program, native, case)
    finally:
        e.unicorn.Uc = original
    assert events == [["rotation-type-change", case["records"][0]["type_id"], new_type], ["restore-after-draw"]], events
    return result, events


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
    sources = {
        "retained": args.source.read_text(),
        "before": (match.DEFAULT_MATCH_ROOT / "evidence/fire-overlay-lifetimes-2026-09-13/before.cpp").read_text(),
    }
    controls = json.loads((HERE / "source-controls.json").read_text())
    assert e.sha(sources["before"].encode()) == controls["baseline_sha256"]
    assert e.sha(sources["retained"].encode()) == controls["retained_sha256"]
    assert config.compiler == controls["compiler"] and config.cflags == controls["cflags"]
    assert json.loads(json.dumps(config.reference_aliases)) == controls["reference_aliases"]
    pinned = json.loads((FIRE_PROOF.parent / "results.json").read_text())
    assert e.sha(match.default_image_path().read_bytes()) == pinned["image_sha256"]
    line = "        type_id = projectile->pos.tail.vy.type_id;\n"
    assert sources["retained"].count(line) == 1
    sources["no-reload"] = sources["retained"].replace(line, "")
    programs = {}
    for name, source in sources.items():
        d = args.out / name
        d.mkdir(exist_ok=True)
        (d / config.source).write_text(source)
        programs[name] = e.Program(replace(config, directory=d))
    retained = programs["retained"]
    assert (
        e.sha(retained.image.function_bytes(retained.native_start, retained.native_end)) == pinned["native_body_sha256"]
    )
    fixture_rows = []
    failures = {name: [] for name in programs}
    cases = [("fire", c) for c in f.matrix()] + [("billboard", c) for c in billboard_cases()]
    for index, (kind, case) in enumerate(cases):
        native = e.run(programs["retained"], True, case)
        expected = f.oracle(case, native) if kind == "fire" else quad_oracle(case, native)
        fixture_rows.append(
            {
                "index": index,
                "kind": kind,
                "case": case,
                "expected": expected,
                "native_trace_sha256": f.digest(native["calls"]),
                "pools": native["pools"],
                "writes": native["writes"],
            },
        )
        for name, p in programs.items():
            _, c = f.compare(p, case, native)
            if native["calls"] != c["calls"]:
                failures[name].append(index)
    assert not failures["retained"] and not failures["no-reload"]
    assert [i for i in failures["before"] if i < 608] == [
        row["index"] for row in pinned["failures"]["arguments/baseline-inner"]
    ]
    assert len([i for i in failures["before"] if i >= 608]) == 24
    callback_rows = []
    for from_type in HALF:
        for to_type in HALF:
            if from_type == to_type:
                continue
            for cw in (0x007F, 0x037F):
                case = {
                    "records": [
                        f.record(3, [111.25, 208.5], type_id=from_type),
                        f.record(95, [0.0, 0.0], type_id=1, active=0),
                    ],
                    "camera": [4.25, -9.5],
                    "alpha": e.f32(0.7),
                    "glow": 0,
                    "fpcw": cw,
                }
                native, events = callback_run(programs["retained"], True, case, to_type)
                expected = quad_oracle(case, native, to_type)
                right, _ = callback_run(programs["retained"], False, case, to_type)
                wrong, _ = callback_run(programs["no-reload"], False, case, to_type)
                assert native["calls"] == right["calls"] and native["calls"] != wrong["calls"]
                assert (
                    native["pools"] == right["pools"] == wrong["pools"]
                    and native["writes"] == right["writes"] == wrong["writes"]
                )
                callback_rows.append(
                    {
                        "case": case,
                        "to_type": to_type,
                        "expected": expected,
                        "events": events,
                        "native_trace_sha256": f.digest(native["calls"]),
                        "wrong_trace_sha256": f.digest(wrong["calls"]),
                    },
                )
    fixture_text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in fixture_rows)
    assert fixture_text == (HERE / "fixtures.jsonl").read_text()
    (args.out / "fixtures.jsonl").write_text(fixture_text)
    receipt = {
        "source_sha256": e.sha(args.source.read_bytes()),
        "verifier_sha256": e.sha(Path(__file__).read_bytes()),
        "fire_proof_sha256": e.sha(FIRE_PROOF.read_bytes()),
        "controls_sha256": e.sha((HERE / "source-controls.json").read_bytes()),
        "executor_sha256": e.sha(f.EXECUTOR.read_bytes()),
        "engine_sha256": e.sha(e.ENGINE.read_bytes()),
        "image_sha256": e.sha(match.default_image_path().read_bytes()),
        "native_body_sha256": e.sha(
            programs["retained"].image.function_bytes(
                programs["retained"].native_start,
                programs["retained"].native_end,
            ),
        ),
        "unicorn_version": e.unicorn.__version__,
        "fixtures": {"count": len(cases), "sha256": e.sha(fixture_text.encode())},
        "failures": failures,
        "callbacks": callback_rows,
        "programs": {
            n: {
                "source_sha256": e.sha(sources[n].encode()),
                "body_sha256": e.sha(p.body.data),
                "object_sha256": e.sha(p.object_path.read_bytes()),
                "metrics": f.reconstruction.metrics(p.result),
                "frame": match.match_result_payload(p.result)["stack_frame"],
            }
            for n, p in programs.items()
        },
        "scope": "Finite native caller fixtures with unchanged baseline external contracts; callback controls temporarily alter type during billboard rotation and restore it at draw. No assertion that real Grim performs this mutation, no GPU or all-input proof.",
    }
    (args.out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        json.dumps(
            {
                "cases": len(cases),
                "failures": {n: len(x) for n, x in failures.items()},
                "callbacks": len(callback_rows),
            },
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
