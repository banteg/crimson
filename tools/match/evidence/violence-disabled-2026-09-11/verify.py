"""Audit native violence-flag references and low-health blood suppression.

The original player_update and blood-splatter helper execute as machine code.
The candidate player_update uses the same original helper. Allocation, sound,
input and RNG callbacks retain the existing player runner's explicit models.
"""

import argparse
import hashlib
import itertools
import json
import struct
import sys
from dataclasses import replace
from pathlib import Path

import capstone

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / "player-aim-direction-2026-09-11"
sys.path.insert(0, str(SHARED))
import runner

match = runner.e.match
IMAGE_SHA = "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2) + "\n").encode()


def branch_inventory(program):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    flag = program.address("config_violence_disabled")
    blob = program.address("config_blob")
    assert flag - blob == 0x46C
    direct, indirect_offset, pointer_literals = [], [], []
    for function in match.load_function_manifest(scope="all").functions:
        code = program.image.function_bytes(function.address, function.end)
        for ins in md.disasm(code, function.address):
            for operand in ins.operands:
                if operand.type == capstone.CS_OP_IMM and operand.imm == flag:
                    pointer_literals.append({"function": function.name, "address": hex(ins.address),
                                             "instruction": f"{ins.mnemonic} {ins.op_str}"})
                if operand.type == capstone.CS_OP_MEM:
                    mem = operand.mem
                    if mem.base == mem.index == 0 and mem.disp == flag:
                        direct.append({
                            "function": function.name,
                            "address": hex(ins.address),
                            "instruction": f"{ins.mnemonic} {ins.op_str}",
                            "read": bool(operand.access & capstone.CS_AC_READ),
                            "write": bool(operand.access & capstone.CS_AC_WRITE),
                        })
                    elif mem.base != 0 and mem.disp == flag - blob:
                        indirect_offset.append({
                            "function": function.name,
                            "address": hex(ins.address),
                            "instruction": f"{ins.mnemonic} {ins.op_str}",
                        })
    assert len(direct) == 11
    return {"flag_address": hex(flag), "config_offset": hex(flag - blob),
            "direct_references": direct, "register_relative_offset_candidates": indirect_offset,
            "literal_flag_address_candidates": pointer_literals}


def scenarios():
    for index, gore, health, timer_kind, dt in itertools.product(
        (0, 1), (0, 1, 255), (0.0, 19.0, 19.999998092651367, 20.0),
        ("sentinel", "expired", "crosses", "exact-zero"), (0.008, 0.016),
    ):
        timer = {"sentinel": 100.0, "expired": 0.0, "crosses": dt / 2, "exact-zero": dt}[timer_kind]
        yield {"name": f"p{index}-gore{gore}-hp{health}-{timer_kind}-dt{dt}", "frame": {
            "index": index, "violence_disabled": gore, "health": health,
            "low_health_timer": timer, "dt": dt, "seed": 12345 + index,
            "movement": 2, "move_speed": 0.0, "aim": 1, "keys": [],
            "aim_heading": 1.25 if index == 0 else -3.1415927410125732,
            "pos_x": 111.25, "pos_y": 208.5,
        }}


def run(program, native, frame):
    initial_image = program.image
    mapped = bytearray(initial_image.mapped)
    mapped[program.address("config_violence_disabled") - initial_image.image_base] = frame["violence_disabled"]
    # Stable, adjacent sample IDs for the modeled sound API; no audio backend.
    struct.pack_into("<i", mapped, program.address("sfx_bloodspill_01") - initial_image.image_base, 501)
    program.image = replace(initial_image, mapped=bytes(mapped))
    try:
        return runner.run(program, native, frame)
    finally:
        program.image = initial_image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert runner.u.__version__ == "2.1.4"
    assert sha(match.default_image_path().read_bytes()) == IMAGE_SHA
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches/player_update")
    build = args.out / "player_update"
    build.mkdir(exist_ok=True)
    source = (config.directory / config.source).read_bytes()
    (build / config.source).write_bytes(source)
    program = runner.e.Program(replace(config, directory=build))
    manifest = match.load_function_manifest(scope="all")
    _, start, end = match.resolve_function(manifest, "effect_spawn_blood_splatter")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    helper_code = program.image.function_bytes(start, end)
    helper_pcs = {ins.address for ins in md.disasm(helper_code, start)}
    for native in (True, False):
        data = runner.execution_data(program, native)
        # The runner checks admitted helper PCs before its callback models.
        # Admit only this actual body, so the blood helper executes unchanged.
        program._player_update_execution[native] = (*data[:4], data[4] | helper_pcs)
    inventory = branch_inventory(program)
    observations, witnesses = [], []
    missing_flag_control = None
    for case in scenarios():
        frame = case["frame"]
        native = run(program, True, frame)
        candidate = run(program, False, frame)
        keys = ("state", "calls", "writes")
        assert {key: native[key] for key in keys} == {key: candidate[key] for key in keys}, case["name"]
        blood = [row[1] for row in native["calls"] if row[0] == "effect_spawn"]
        sound = [row[1] for row in native["calls"] if row[0] == "sfx_play_panned"]
        draws = [row[1] for row in native["calls"] if row[0] == "rand"]
        players = bytes.fromhex(native["state"]["players"])
        timer_word = struct.unpack_from("<I", players, frame["index"] * 864 + 784)[0]
        rng_state = frame["seed"]
        for draw in draws:
            rng_state = (rng_state * 214013 + 2531011) & 0xFFFFFFFF
            assert draw == (rng_state >> 16) & 32767
        witnesses.append({"input": case, "expected": {
            "timer_bits": timer_word,
            "effects": [{"effect_id": row[0], "position_bits": row[1],
                         "template_bits": list(struct.unpack("<15I", bytes.fromhex(row[2])))} for row in blood],
            "sounds": [{"sample_offset": row[0] - 501, "position_bits": row[1], "gain_bits": row[2]} for row in sound],
            "rng_draws": draws, "rng_state": rng_state,
        }})
        observations.append({"name": case["name"], "observation_sha256": sha(encoded({key: native[key] for key in keys}))})
        if missing_flag_control is None and frame["violence_disabled"] == 1 and blood == [] and len(draws) == 1:
            wrong = run(program, True, {**frame, "violence_disabled": 0})
            assert wrong["calls"] != native["calls"]
            wrong_effects = sum(row[0] == "effect_spawn" for row in wrong["calls"])
            wrong_rng_draws = sum(row[0] == "rand" for row in wrong["calls"])
            assert wrong_effects == 6 and wrong_rng_draws == 31
            missing_flag_control = {
                "case": case["name"], "detected": True,
                "correct_effects": 0, "wrong_effects": wrong_effects,
                "correct_rng_draws": 1, "wrong_rng_draws": wrong_rng_draws,
            }
    assert missing_flag_control is not None
    fixture = {"fpcw": 0x7F, "cases": witnesses}
    (args.out / "witnesses.json").write_bytes(encoded(fixture))
    result = {
        "image_sha256": IMAGE_SHA,
        "script_sha256": sha(Path(__file__).read_bytes()),
        "runner_sha256": sha((SHARED / "runner.py").read_bytes()),
        "engine_sha256": sha(runner.ENGINE.read_bytes()),
        "source_sha256": sha(source), "body_sha256": sha(program.body.data),
        "native_blood_helper_sha256": sha(helper_code),
        "witnesses_sha256": sha(encoded(fixture)),
        "scope": "player_update and original blood helper; allocation, RNG, sound and input are explicit callback models",
        "violence_flag_inventory": inventory,
        "missing_flag_control": missing_flag_control,
        "native_candidate_agree": len(observations), "cases": observations,
    }
    (args.out / "results.json").write_bytes(encoded(result))
    print(json.dumps({"cases": len(observations), "direct_flag_references": len(inventory["direct_references"])}))


if __name__ == "__main__":
    main()
