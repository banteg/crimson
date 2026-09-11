"""Execute original and compiled corpse queue bodies and staged-death callers."""

import argparse
import hashlib
import itertools
import json
import struct
import sys
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
CALLER = HERE.parent / "creature-state-publication-2026-09-11" / "execute.py"
sys.path.insert(0, str(CALLER.parent))
import execute as updates

e = updates.engine
u, x = e.unicorn, e.x86
IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
ARRAYS = {"fx_rotated_pos_x": 8, "fx_rotated_color_r": 16,
          "fx_rotated_rotation": 4, "fx_rotated_scale": 4, "fx_rotated_effect_id": 4}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def floats(words):
    return list(struct.unpack("<" + "f" * len(words), struct.pack("<" + "I" * len(words), *words)))


def build(out, name, caller=False):
    config = e.match.load_scratch_config(e.match.DEFAULT_MATCH_ROOT / "scratches" / name)
    directory = out / name
    directory.mkdir(exist_ok=True)
    (directory / config.source).write_bytes((config.directory / config.source).read_bytes())
    config = replace(config, directory=directory)
    return updates.Comparison(config) if caller else e.Program(config)


def run(p, native, case):
    assert 0 <= case["count"] <= 63
    mu = u.Uc(u.UC_ARCH_X86, u.UC_MODE_32)
    mu.mem_map(p.image.image_base, e.page_size(p.image.size_of_image))
    mu.mem_write(p.image.image_base, p.image.mapped)
    mu.mem_map(e.CODE, p.code_size)
    for address, data in p.patched_sections.items():
        if data:
            mu.mem_write(address, data)
    mu.mem_map(e.STACK, 65536)
    mu.mem_write(e.STACK, b"\xa5" * 65536)
    mu.mem_map(e.STUB, 16384)
    regions = [(p.address(name), p.address(name) + 64 * stride) for name, stride in ARRAYS.items()]
    regions.append((p.address("fx_queue_rotated"), p.address("fx_queue_rotated") + 4))
    regions.sort()
    assert all(end <= next_start for (_, end), (next_start, _) in itertools.pairwise(regions))
    for start, end in regions:
        mu.mem_write(start, b"\xa5" * (end - start))
    mu.mem_write(p.address("fx_queue_rotated"), struct.pack("<i", case["count"]))
    mu.mem_write(p.address("terrain_texture_failed"), bytes([case["failed"]]))
    mu.mem_write(p.address("cv_terrainBodiesTransparency"), struct.pack("<I", e.STUB))
    mu.mem_write(e.STUB + 12, struct.pack("<f", case["transparency"]))
    mu.mem_write(e.STUB + 32, struct.pack("<2f4f", *case["pos"], *case["color"]))
    readonly = [(e.STUB, 56), (p.address("terrain_texture_failed"), 1),
                (p.address("cv_terrainBodiesTransparency"), 4)]
    before = [bytes(mu.mem_read(a, n)) for a, n in readonly]
    esp = e.STACK + 0xF000
    mu.mem_write(esp, struct.pack("<IIIffi", e.STOP, e.STUB + 32, e.STUB + 40,
                                  case["rotation"], case["scale"], case["type_id"]))
    mu.reg_write(x.UC_X86_REG_ESP, esp)
    mu.reg_write(x.UC_X86_REG_FPCW, 0x7F)
    mu.reg_write(x.UC_X86_REG_FPTAG, 0xFFFF)
    saved = [(x.UC_X86_REG_EBX, 0x12345678), (x.UC_X86_REG_ESI, 0x23456789),
             (x.UC_X86_REG_EDI, 0x34567890), (x.UC_X86_REG_EBP, 0x45678901)]
    for reg, value in saved:
        mu.reg_write(reg, value)
    start = p.native_start if native else p.candidate_start
    instructions = p.result.target_disassembly if native else p.result.candidate_disassembly
    admitted = {start + ins.offset for ins in instructions}
    coverage, writes = set(), []

    def step(uc, address, size, data):
        assert address in admitted, hex(address)
        coverage.add(address - start)

    def write(uc, access, address, size, value, data):
        if e.STACK <= address and address + size <= e.STACK + 65536:
            return
        assert any(a <= address and address + size <= b for a, b in regions), (hex(address), size)
        writes.append([address, size, value & ((1 << (8 * size)) - 1)])

    mu.hook_add(u.UC_HOOK_CODE, step)
    mu.hook_add(u.UC_HOOK_MEM_WRITE, write)
    mu.emu_start(start, e.STOP, count=1000)
    assert mu.reg_read(x.UC_X86_REG_EIP) == e.STOP
    assert mu.reg_read(x.UC_X86_REG_ESP) == esp + 4
    assert mu.reg_read(x.UC_X86_REG_FPCW) == 0x7F
    assert mu.reg_read(x.UC_X86_REG_FPTAG) == 0xFFFF
    for reg, value in saved:
        assert mu.reg_read(reg) == value
    assert before == [bytes(mu.mem_read(a, n)) for a, n in readonly]
    count = struct.unpack("<i", mu.mem_read(p.address("fx_queue_rotated"), 4))[0]
    added = count == case["count"] + 1
    entry = None
    if added:
        def words(name):
            stride = ARRAYS[name]
            return list(struct.unpack("<" + "I" * (stride // 4),
                                      mu.mem_read(p.address(name) + case["count"] * stride, stride)))
        entry = {"pos_bits": words("fx_rotated_pos_x"), "color_bits": words("fx_rotated_color_r"),
                 "rotation_bits": words("fx_rotated_rotation")[0], "scale_bits": words("fx_rotated_scale")[0],
                 "type_id": case["type_id"]}
        assert words("fx_rotated_effect_id") == [case["type_id"] & 0xFFFFFFFF]
    # Every other slot must retain its initial sentinel, including the unused slot 63.
    for name, stride in ARRAYS.items():
        for index in range(64):
            if added and index == case["count"]:
                continue
            assert bytes(mu.mem_read(p.address(name) + index * stride, stride)) == b"\xa5" * stride
    return {"return": mu.reg_read(x.UC_X86_REG_EAX) & 255, "count": count, "entry": entry,
            "writes": writes, "coverage": sorted(coverage)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert u.__version__ == "2.1.4"
    assert sha(e.match.default_image_path().read_bytes()) == IMAGE_SHA
    p = build(args.out, "fx_queue_add_rotated")
    caller = build(args.out, "creature_update_all", caller=True)
    queue_rows, caller_rows, coverage, observations = [], [], set(), []
    for count, failed, alpha, transparency in itertools.product(
        (0, 1, 62, 63), (0, 1), (0.0, 0.125, 0.8, 1.0, 1.1, -0.1), (0.0, 0.3, 1.0, 2.0, -1.0),
    ):
        case = {"count": count, "failed": failed, "transparency": transparency,
                "pos": [120.3, -230.7], "color": [0.6, 0.4, 0.8, alpha],
                "rotation": -1.3, "scale": 40.3, "type_id": 7}
        native, candidate = run(p, True, case), run(p, False, case)
        assert native == candidate, case
        coverage.update(native["coverage"])
        observations.append(sha(encoded(native)))
        queue_rows.append({"input": case, "expected": {k: native[k] for k in ("return", "count", "entry")}})
    for flags, gore, queued, size in itertools.product((0, 4, 16, 20), (0, 1), (0, 1), (0.0, 0.25, 40.3, 130.0)):
        creature = {"lifecycle_stage": 0.1, "flags": flags, "health": 0.0, "size": size,
                    "type_id": 3, "pos_x": 120.3, "pos_y": -230.7, "heading": -1.3,
                    "tint_r": 0.6, "tint_g": 0.4, "tint_b": 0.8, "tint_a": 0.7}
        case = {"dt": 0.016, "fpcw": 0x7F, "fade": 1, "violence": gore,
                "queued": queued, "creatures": [creature]}
        native, candidate = caller.run(True, case), caller.run(False, case)
        for key in ("state", "players", "slots", "scalars", "calls", "writes", "model_writes"):
            assert native[key] == candidate[key], (case, key)
        calls = [row[1:] for row in native["calls"] if row[0] == "fx_queue_add_rotated"]
        assert len(calls) == (1 if gore == 0 else 0)
        entry = None
        if calls:
            pos, color, rotation, scale, type_id = calls[0]
            composed = run(p, True, {"count": 0 if queued else 63, "failed": 0, "transparency": 0.0,
                                     "pos": floats(pos), "color": floats(color),
                                     "rotation": floats([rotation])[0], "scale": floats([scale])[0], "type_id": type_id})
            assert composed["return"] == queued
            entry = composed["entry"]
        caller_rows.append({"input": case, "expected": {"queue_calls": calls, "entry": entry,
                            "lifecycle_bits": struct.unpack_from("<I", native["state"], 16)[0],
                            "kill_count": struct.unpack("<i", bytes.fromhex(native["scalars"]["creature_kill_count"]))[0] - 11}})
    # Real witnesses must distinguish the original port's white tint, missing attenuation,
    # direct division, and minimum-size clamp from native outputs.
    controls = {
        "missing_alpha_adjustment": any(row["expected"]["entry"] is not None and
            row["expected"]["entry"]["color_bits"][3] != e.bits(row["input"]["color"][3]) for row in queue_rows),
        "direct_division": any(row["expected"]["entry"] is not None and row["input"]["transparency"] != 0 and
            row["expected"]["entry"]["color_bits"][3] != e.bits(e.f32(row["input"]["color"][3]) / e.f32(row["input"]["transparency"])) for row in queue_rows),
        "white_tint": any(row["expected"]["entry"] is not None and row["expected"]["entry"]["color_bits"][:3] != [e.bits(1)] * 3 for row in caller_rows),
        "minimum_size": any(row["expected"]["entry"] is not None and row["input"]["creatures"][0]["size"] < 1 and
            row["expected"]["entry"]["scale_bits"] != e.bits(1) for row in caller_rows),
    }
    assert all(controls.values()), controls
    fixture = {"fpcw": 0x7F, "queue": queue_rows, "callers": caller_rows}
    (args.out / "witnesses.json").write_bytes(encoded(fixture))
    result = {"image_sha256": IMAGE_SHA, "script_sha256": sha(Path(__file__).read_bytes()),
              "engine_sha256": sha(updates.ENGINE_PATH.read_bytes()), "caller_runner_sha256": sha(CALLER.read_bytes()),
              "sources": {program.config.function: {"source_sha256": sha((program.config.directory / program.config.source).read_bytes()),
                         "body_sha256": sha(program.body.data)} for program in (p, caller.program)},
              "witnesses_sha256": sha(encoded(fixture)), "queue_cases": len(queue_rows), "caller_cases": len(caller_rows),
              "queue_coverage_offsets": sorted(coverage), "queue_instruction_count": len(p.result.target_disassembly),
              "negative_controls": controls, "queue_observation_hashes": observations}
    (args.out / "results.json").write_bytes(encoded(result))
    print(json.dumps({k: result[k] for k in ("queue_cases", "caller_cases", "negative_controls")}))


if __name__ == "__main__":
    main()
