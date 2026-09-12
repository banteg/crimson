"""Check ion strip widening and the independently isolated endpoint rounding defect."""

import argparse
import importlib.util
import json
import random
import struct
from dataclasses import asdict, replace
from pathlib import Path

from crimson import match

HERE = Path(__file__).resolve().parent
ENGINE = HERE.parent / "plasma-head-alpha-2026-09-10/verify.py"
RECONSTRUCTION = HERE.parent / "renderer-house-style-2026-09-13/verify_controls.py"


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


p = module("ion_endpoint_engine", ENGINE)
reconstruction = module("ion_endpoint_reconstruction", RECONSTRUCTION)
SCALES = {21: p.f32(2.2), 22: p.f32(1.05), 23: p.f32(3.5)}
STATE_KEYS = (
    "state_sha256",
    "creature_state_sha256",
    "secondary_state_sha256",
    "player_state_sha256",
    "search_results",
    "native_search_sha256",
)


def arguments(case):
    return (case["type_id"], case["life"], case["alpha"], case["glow"]), {
        "position": case["position"],
        "origin": case["origin"],
        "beam_stubs": True,
        "native_creature_search": True,
        "creature_rows": [(1, *case["target"], 1, 16.0, 40.0)],
        "perk_count": case["perk"],
    }


def run(program, native, case):
    """Reuse the historical executor, changing only camera and initial precision.

    The factory override is serial. Its entry adapter leaves instructions and
    callbacks untouched, and additionally checks pool, caller and x87 state.
    """
    assert case["fpcw"] in (0x007F, 0x037F)
    original = p.unicorn.Uc

    def factory(*args, **kwargs):
        uc = original(*args, **kwargs)
        emu_start = uc.emu_start

        def execute(*args, **kwargs):
            uc.mem_write(program.address("camera_offset"), struct.pack("<2f", *case["camera"]))
            uc.reg_write(p.x86.UC_X86_REG_FPCW, case["fpcw"])
            esp = uc.reg_read(p.x86.UC_X86_REG_ESP)
            guard = bytes(uc.mem_read(esp, 0x100))
            pools = {
                name: bytes(uc.mem_read(program.address(name), size))
                for name, size in (
                    ("projectile_pool", 0x40 * 96),
                    ("creature_pool", 0x98 * 384),
                    ("secondary_projectile_pool", 0x2C * 64),
                    ("player_state_table", 0x360 * 2),
                )
            }
            emu_start(*args, **kwargs)
            assert uc.reg_read(p.x86.UC_X86_REG_FPCW) == case["fpcw"]
            assert uc.reg_read(p.x86.UC_X86_REG_FPTAG) == 0xFFFF
            assert bytes(uc.mem_read(esp, 0x100)) == guard
            for name, before in pools.items():
                assert bytes(uc.mem_read(program.address(name), len(before))) == before

        uc.emu_start = execute
        return uc

    positional, keywords = arguments(case)
    p.unicorn.Uc = factory
    try:
        return p.run(program, native, *positional, **keywords)
    finally:
        p.unicorn.Uc = original


def matrix():
    rng = random.Random(0x424E0B)
    rows = []
    for index in range(256):
        position = [p.f32(rng.uniform(-512, 512)) for _ in range(2)]
        target = [p.f32(x + rng.uniform(-20, 20)) for x in position]
        origin = [p.f32(x + rng.uniform(-40, 40)) for x in position]
        camera = [p.f32(rng.uniform(-512, 512)) for _ in range(2)]
        for cw in (0x007F, 0x037F):
            rows.append(
                {
                    "position": position,
                    "target": target,
                    "origin": origin,
                    "camera": camera,
                    "fpcw": cw,
                    "type_id": (21, 22, 23)[index % 3],
                    "life": p.f32(0.2),
                    "alpha": p.f32(0.7),
                    "glow": index % 2,
                    "perk": (index // 2) % 2,
                },
            )
    for type_id, (camera_value, target_value) in {21: (32.0, 3.2), 22: (16.0, 0.8), 23: (55.2, 0.8)}.items():
        for axis in (0, 1):
            camera, target = [0.0, 0.0], [0.0, 0.0]
            camera[axis], target[axis] = p.f32(camera_value), p.f32(target_value)
            for cw in (0x007F, 0x037F):
                rows.append(
                    {
                        "position": [0.0, 0.0],
                        "target": target,
                        "origin": [1.0, 0.0],
                        "camera": camera,
                        "fpcw": cw,
                        "type_id": type_id,
                        "life": p.f32(0.2),
                        "alpha": 1.0,
                        "glow": 0,
                        "perk": 0,
                    },
                )
    assert len(rows) == 524
    return rows


def endpoint_oracle(case):
    scale = SCALES[case["type_id"]]
    half_size = p.f32(scale * 16.0)
    sums = [x + y for x, y in zip(case["camera"], case["target"], strict=True)]
    if case["fpcw"] == 0x007F:
        sums = [p.f32(x) for x in sums]
    # These bounded float32 sums/subtractions are exact in binary64 at PC64.
    return [*(p.bits(x - half_size) for x in sums), p.bits(scale * 32.0), p.bits(scale * 32.0)]


def adapter_control(program):
    case = {
        "position": [111.25, 208.5],
        "origin": [50.125, 91.75],
        "target": [125.5, 180.0],
        "camera": [13.125, -21.75],
        "fpcw": 0x037F,
        "type_id": 23,
        "life": p.f32(0.2),
        "alpha": p.f32(0.7),
        "glow": 0,
        "perk": 0,
    }
    positional, keywords = arguments(case)
    for native in (True, False):
        assert run(program, native, case) == p.run(program, native, *positional, **keywords)


def native_window(program):
    md = p.capstone.Cs(p.capstone.CS_ARCH_X86, p.capstone.CS_MODE_32)
    instructions = list(md.disasm(program.image.function_bytes(0x424F44, 0x424F86), 0x424F44))
    x87 = [(ins.mnemonic, ins.op_str) for ins in instructions if ins.mnemonic.startswith("f")]
    assert x87 == [
        ("fld", "dword ptr [0x484fcc]"),
        ("fadd", "dword ptr [esi + 0x49bf50]"),
        ("fsub", "dword ptr [esp + 0xac]"),
        ("fstp", "dword ptr [esp]"),
        ("fld", "dword ptr [0x484fc8]"),
        ("fadd", "dword ptr [esi + 0x49bf4c]"),
        ("fsub", "dword ptr [esp + 0xb4]"),
        ("fstp", "dword ptr [esp]"),
    ]
    return [
        {"address": hex(i.address), "bytes": bytes(i.bytes).hex(), "text": f"{i.mnemonic} {i.op_str}"}
        for i in instructions
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/projectile_render")
    manifest = json.loads((HERE / "source-controls.json").read_text())
    before = (HERE / "before.cpp").read_text()
    assert p.sha(before.encode()) == manifest["baseline_sha256"]
    assert config.compiler == manifest["compiler"] and config.cflags == manifest["cflags"]
    assert json.loads(json.dumps(config.reference_aliases)) == manifest["reference_aliases"]
    pinned = json.loads((HERE.parent / "ion-chain-product-2026-09-10/results.json").read_text())
    assert p.sha(match.default_image_path().read_bytes()) == pinned["image_sha256"]
    programs = {}
    for control in manifest["controls"]:
        directory = args.out / control["name"]
        directory.mkdir(exist_ok=True)
        (directory / config.source).write_text(reconstruction.reconstruct(before, control))
        programs[control["name"]] = p.Program(replace(config, directory=directory))
    fixed = programs["endpoint-reload"]
    assert p.sha(fixed.image.function_bytes(fixed.native_start, fixed.native_end)) == pinned["native_body_sha256"]
    adapter_control(fixed)
    window = native_window(fixed)
    failures = {name: {"first_strip": [], "second_strip": [], "trace": []} for name in programs}
    fixtures, differences = [], []
    for index, case in enumerate(matrix()):
        native = run(fixed, True, case)
        endpoint_index = native["return_sites"].index(0x424F86)
        expected = endpoint_oracle(case)
        assert native["calls"][endpoint_index] == ["grim_draw_quad", expected]
        native_quads = [a for name, a in native["calls"] if name == "grim_draw_quad_points"]
        assert len(native_quads) == 2 and native["search_results"] == [1, 0xFFFFFFFF]
        fixtures.append(
            {
                "index": index,
                "case": case,
                "strips": native_quads,
                "endpoint": expected,
                "native_trace_sha256": p.sha(json.dumps(native["calls"]).encode()),
                "state": {key: native[key] for key in STATE_KEYS},
            },
        )
        for name, program in programs.items():
            candidate = run(program, False, case)
            assert all(native[key] == candidate[key] for key in STATE_KEYS)
            quads = [a for label, a in candidate["calls"] if label == "grim_draw_quad_points"]
            assert len(quads) == 2
            for part, label in enumerate(("first_strip", "second_strip")):
                if native_quads[part] != quads[part]:
                    failures[name][label].append(index)
            if native["calls"] != candidate["calls"]:
                failures[name]["trace"].append(index)
                if name == "before":
                    changed = [
                        i for i, (a, b) in enumerate(zip(native["calls"], candidate["calls"], strict=True)) if a != b
                    ]
                    assert changed == [endpoint_index]
                    differences.append(
                        {"index": index, "native": expected, "before": candidate["calls"][endpoint_index][1]},
                    )
        if index % 100 == 0:
            print(f"Checked {index} cases", flush=True)
    for name in ("endpoint-reload", "endpoint-pointer", "endpoint-ctor"):
        assert not any(failures[name].values()), (name, failures[name])
    assert len(failures["before"]["trace"]) == 69
    assert all(fixtures[i]["case"]["fpcw"] == 0x037F for i in failures["before"]["trace"])
    for name in ("before", "repeated", "native-order"):
        assert not failures[name]["first_strip"] and not failures[name]["second_strip"]
        assert failures[name]["trace"] == failures["before"]["trace"]
    assert not failures["wrong-widen"]["first_strip"]
    assert failures["wrong-widen"]["second_strip"] == list(range(524))
    minimal = fixtures[517]
    assert minimal["case"]["type_id"] == 22 and minimal["endpoint"][0] == 0x35500000
    fixture_text = "".join(json.dumps(row, sort_keys=True) + "\n" for row in fixtures)
    if (HERE / "fixtures.jsonl").exists():
        assert fixture_text == (HERE / "fixtures.jsonl").read_text()
    (args.out / "fixtures.jsonl").write_text(fixture_text)
    receipt = {
        "image_sha256": pinned["image_sha256"],
        "native_body_sha256": pinned["native_body_sha256"],
        "verifier_sha256": p.sha(Path(__file__).read_bytes()),
        "engine_sha256": p.sha(ENGINE.read_bytes()),
        "reconstruction_sha256": p.sha(RECONSTRUCTION.read_bytes()),
        "controls_sha256": p.sha((HERE / "source-controls.json").read_bytes()),
        "unicorn_version": p.unicorn.__version__,
        "adapter_self_control": "passed for native and candidate",
        "native_endpoint_window": window,
        "fixtures": {"count": len(fixtures), "sha256": p.sha(fixture_text.encode())},
        "failures": failures,
        "endpoint_differences": differences,
        "programs": {
            name: {
                "source_sha256": p.sha((program.config.directory / config.source).read_bytes()),
                "object_sha256": p.sha(program.object_path.read_bytes()),
                "body_sha256": p.sha(program.body.data),
                "metrics": reconstruction.metrics(program.result),
                "frame": match.match_result_payload(program.result)["stack_frame"],
                "reference_problems": [
                    asdict(e) for e in program.result.masked_operand_audit.entries if e.status != "ok"
                ],
            }
            for name, program in programs.items()
        },
        "scope": "Finite caller fixtures, native creature search and x87 arithmetic, modeled D3DX/Grim callbacks. No reproduced widening defect in these cases; the endpoint defect is PC64-only here. No GPU or arbitrary-input equivalence claim.",
    }
    (args.out / "results.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"All {len(fixtures)} fixed traces agree; {len(differences)} old endpoint failures reproduced.", flush=True)


if __name__ == "__main__":
    main()
