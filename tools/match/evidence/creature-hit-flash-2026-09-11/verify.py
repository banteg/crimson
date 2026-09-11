"""Record native flash draw, color packing, damage, and countdown witnesses.

The game and C++ renderer/update/damage bodies execute under existing guarded
observers. Grim2D's color-pointer body executes separately, with its imported
_ftol resolved to the game's native converter as an explicit ABI model.
This is a bounded CPU/call audit, not GPU or whole-frame equivalence.
"""

import argparse
import hashlib
import importlib.util
import itertools
import json
import struct
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import capstone
import unicorn
from unicorn import x86_const as x86

from crimson import match

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parent
sys.path.insert(0, str(EVIDENCE / "creature-frame-selection-2026-09-11"))
import runner as frames


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


updates = load("flash_update", EVIDENCE / "creature-state-publication-2026-09-11/execute.py")
impacts = load("flash_damage", EVIDENCE / "primary-impact-presentation-2026-09-11/execute.py")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=lambda item: item.hex()).encode()


def f32(value):
    return struct.unpack("<f", struct.pack("<f", value))[0]


def bits(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


def build_config(function, out):
    config = match.load_scratch_config(match.DEFAULT_MATCH_ROOT / "scratches" / function)
    directory = out / function
    directory.mkdir(exist_ok=True)
    source = (config.directory / config.source).read_bytes()
    (directory / "scratch.cpp").write_bytes(source)
    return replace(config, directory=directory, source="scratch.cpp"), sha(source)


class NativeColor:
    def __init__(self):
        name = "grim.dll"
        self.image = match.load_image(match.default_image_path(name))
        manifest = match.load_function_manifest(
            match.default_functions_path(name),
            metadata_path=match.default_metadata_path(name),
            image_name=name,
            scope="all",
        )
        catalog = match.load_reference_catalog(manifest)
        _, self.start, end = match.resolve_function(manifest, "grim_set_color_ptr")
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        instructions = list(md.disasm(self.image.function_bytes(self.start, end), self.start))
        calls = {int(row.op_str, 16) for row in instructions if row.mnemonic == "call"}
        assert len(calls) == 1
        _, crt_start, crt_end = match.resolve_function(manifest, hex(calls.pop()))
        self.allowed = {row.address for row in instructions}
        thunk = self.image.function_bytes(crt_start, crt_end)
        assert len(thunk) == 6 and thunk[:2] == b"\xff\x25"
        self.ftol_import = struct.unpack_from("<I", thunk, 2)[0]
        imports = json.loads((match.default_functions_path(name).parent / "imports.json").read_text())
        assert any(
            row["name"] == "_ftol" and int(row["address"], 16) == self.ftol_import
            for library in imports
            for row in library["entries"]
        )
        self.allowed.add(crt_start)
        self.game = match.load_image(match.default_image_path())
        _, self.ftol_start, ftol_end = match.resolve_function(match.load_function_manifest(scope="all"), "crt_ftol")
        self.allowed.update(
            row.address for row in md.disasm(self.game.function_bytes(self.ftol_start, ftol_end), self.ftol_start)
        )
        addresses = catalog._addresses_for_symbol("grim_color_slot0")
        assert len(addresses) == 1
        self.color = addresses[0]
        self.coverage = set()

    def pack(self, words):
        mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        image = self.image
        mu.mem_map(image.image_base, (image.size_of_image + 4095) & -4096)
        mu.mem_write(image.image_base, image.mapped)
        mu.mem_map(self.game.image_base, (self.game.size_of_image + 4095) & -4096)
        mu.mem_write(self.game.image_base, self.game.mapped)
        mu.mem_write(self.ftol_import, struct.pack("<I", self.ftol_start))
        stack, stop = 0x20000000, 0x30000000
        mu.mem_map(stack, 0x10000)
        mu.mem_map(stop, 4096)
        esp, rgba = stack + 0xF000, stack + 0x100
        mu.mem_write(esp, struct.pack("<II", stop, rgba))
        mu.mem_write(rgba, struct.pack("<4I", *words))
        mu.reg_write(x86.UC_X86_REG_ESP, esp)
        mu.reg_write(x86.UC_X86_REG_ESI, 0x12340000)
        mu.reg_write(x86.UC_X86_REG_FPCW, 0x7F)
        mu.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)

        def code(_mu, pc, _size, _data):
            assert pc in self.allowed, hex(pc)
            self.coverage.add(pc)

        def write(_mu, _access, address, size, _value, _data):
            assert stack <= address < stack + 0x10000 or self.color <= address <= self.color + 16 - size

        mu.hook_add(unicorn.UC_HOOK_CODE, code)
        mu.hook_add(unicorn.UC_HOOK_MEM_WRITE, write)
        mu.emu_start(self.start, stop, count=1000)
        assert mu.reg_read(x86.UC_X86_REG_EIP) == stop
        assert mu.reg_read(x86.UC_X86_REG_ESP) == esp + 8
        assert mu.reg_read(x86.UC_X86_REG_ESI) == 0x12340000
        assert mu.reg_read(x86.UC_X86_REG_FPCW) == 0x7F
        assert mu.reg_read(x86.UC_X86_REG_FPTAG) == 0xFFFF
        colors = struct.unpack("<4I", mu.mem_read(self.color, 16))
        assert len(set(colors)) == 1
        return colors[0]


def render_cases():
    for type_id, transition, enabled in itertools.product(range(6), (0.0, 0.001, 0.1, 0.371, 0.5, 0.8, 1.0), (0, 1)):
        creatures = []
        states = itertools.product(
            (-0.1, 0.0, 0.0001, 0.1, 0.2, 0.20000001788139343), (-11.0, -10.0, 7.000000476837158, 16.0),
        )
        for index, (timer, lifecycle) in enumerate(states):
            creatures.append(
                {
                    "index": index,
                    "active": 1,
                    "type_id": type_id,
                    "hit_flash_timer": f32(timer),
                    "lifecycle_stage": f32(lifecycle),
                    "flags": (0, 4, 16, 20, 64, 80)[index % 6],
                    "anim_phase": f32((4.2, 15.5, 23.5)[index % 3]),
                    "size": (16.0, 32.5, 64.0, 200.0)[index % 4],
                    "pos_x": 64.0 + 8 * index,
                    "pos_y": 128.0 + 4 * index,
                    "heading": f32(1.4),
                },
            )
        creatures.extend(
            [
                dict(creatures[-1], index=382, active=0),
                dict(creatures[-1], index=383, type_id=(type_id + 1) % 6),
            ],
        )
        yield {
            "name": f"render-{type_id}-{transition}-{enabled}",
            "type_id": type_id,
            "transition": f32(transition),
            "flash": enabled,
            "shadows": type_id % 2,
            "fpcw": 0x7F,
            "creatures": creatures,
        }


def flash_draws(case, calls, color):
    additive = False
    frame = rotation = rgba = None
    draws = []
    for name, words in calls:
        if name == "grim_set_config_var" and words[0] == 20:
            additive = words[1] == 2
        elif name == "grim_set_atlas_frame":
            frame = words[1]
        elif name == "grim_set_rotation":
            rotation = words[0]
        elif name == "grim_set_color_ptr":
            rgba = words
        elif name == "grim_draw_quad" and additive:
            assert frame is not None and rotation is not None and rgba is not None
            draws.append(
                {
                    "frame": frame,
                    "rgba_bits": rgba,
                    "rotation_bits": rotation,
                    "quad_bits": words,
                    "packed_color": color.pack(rgba),
                },
            )
    assert not additive, "Flash must restore destination alpha blending"
    expected_slots = [
        record["index"]
        for record in case["creatures"]
        if case["flash"]
        and record["active"]
        and record["type_id"] == case["type_id"]
        and record["lifecycle_stage"] >= -10.0
        and record["hit_flash_timer"] > 0
    ]
    assert len(draws) == len(expected_slots) * 2
    pairs = []
    for index, slot in enumerate(expected_slots):
        first, second = draws[index * 2 : index * 2 + 2]
        assert first == second
        pairs.append(dict(first, slot=slot))
    return pairs


def damage_run(program, native, case):
    factory = impacts.unicorn.Uc

    class DamageMachine:
        def __init__(self, *args, **kwargs):
            self.mu = factory(*args, **kwargs)

        def __getattr__(self, name):
            return getattr(self.mu, name)

        def emu_start(self, *args, **kwargs):
            esp = self.mu.reg_read(x86.UC_X86_REG_ESP)
            impulse = impacts.m.STACK + 0x100
            self.mu.mem_write(impulse, struct.pack("<2f", 0, 0))
            self.mu.mem_write(
                esp + 4,
                struct.pack("<IfII", case["creatures"][0]["index"], case["damage"], case["damage_type"], impulse),
            )
            return self.mu.emu_start(*args, **kwargs)

    with patch.object(impacts.unicorn, "Uc", DamageMachine):
        return impacts.run(program, native, case)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert unicorn.__version__ == "2.1.4"
    assert (
        sha(match.default_image_path().read_bytes())
        == "771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4"
    )
    assert sha(match.default_image_path("grim.dll").read_bytes()) == "373f1304511c2cdb06a36447cc96f281a270bfe96957ca8ff03e19cf03dc8e70"
    renderer_config, renderer_sha = build_config("creature_render_type", out)
    layout = frames.parent.check_fixture_layout(renderer_config, out)
    renderer = frames.Comparison(renderer_config, match.compile_scratch(renderer_config))
    color = NativeColor()
    witnesses = {"fpcw": 0x7F, "render": [], "countdown": [], "damage": []}
    receipts = {"render": [], "countdown": [], "damage": []}
    for case in render_cases():
        result = renderer.compare(case)
        assert result["calls_equal"] and result["writes_equal"], case["name"]
        draws = flash_draws(case, result["native"]["calls"], color)
        witnesses["render"].append({"input": case, "expected": draws})
        receipts["render"].append(
            {
                "case": case["name"],
                "calls_sha256": sha(raw(result["native"]["calls"])),
                "writes_sha256": sha(raw(result["native"]["writes"])),
            },
        )
    print(f"Verified {len(witnesses['render'])} render cases", flush=True)
    controls = []
    render_source = (renderer_config.directory / renderer_config.source).read_text()
    quad = """            grim_interface_ptr->grim_draw_quad(
                draw_pos.x, draw_pos.y, creature->size, creature->size);"""
    control_case = next(
        case for case in render_cases() if case["type_id"] == 3 and case["flash"] and case["transition"] == f32(0.371)
    )
    for name, old, new in (
        (
            "wrong-flash-fade",
            "color.a = creature->hit_flash_timer * 5.0f;",
            "color.a = creature->hit_flash_timer * 4.0f;",
        ),
        ("single-flash-quad", quad + "\n" + quad, quad),
    ):
        assert render_source.count(old) == 1
        directory = out / name
        directory.mkdir(exist_ok=True)
        mutated = render_source.replace(old, new)
        (directory / "scratch.cpp").write_text(mutated)
        config = replace(renderer_config, directory=directory)
        wrong = frames.Comparison(config, match.compile_scratch(config))
        result = wrong.compare(control_case)
        assert not result["calls_equal"]
        controls.append(
            {"name": name, "source_sha256": sha(mutated.encode()), "case": control_case["name"], "detected": "calls"},
        )
    update_config, update_sha = build_config("creature_update_all", out)
    updater = updates.Comparison(update_config)
    for dt, freeze in itertools.product((0.0001, 0.016, 0.1, 0.25), (0, 1)):
        records = [
            {
                "index": index,
                "active": index % 2,
                "hit_flash_timer": f32(timer),
                "health": 100 if index % 3 else 0,
                "lifecycle_stage": 16 if index % 3 else 5,
                "move_speed": 0,
                "ai_mode": 1,
            }
            for index, timer in enumerate((-0.1, -0.1, 0, 0, 0.0001, 0.0001, 0.1, 0.1, 0.2, 0.2))
        ]
        records.append(dict(records[-1], index=383))
        case = {"name": f"countdown-{dt}-{freeze}", "dt": f32(dt), "freeze": freeze, "fpcw": 0x7F, "creatures": records}
        native, current = updater.run(True, case), updater.run(False, case)
        keys = ("state", "players", "slots", "scalars", "writes", "model_writes", "calls")
        assert all(native[key] == current[key] for key in keys), case["name"]
        expected = [
            {
                "index": record["index"],
                "timer_bits": struct.unpack_from("<I", native["state"], record["index"] * 152 + 56)[0],
            }
            for record in records
        ]
        witnesses["countdown"].append({"input": case, "expected": expected})
        receipts["countdown"].append(
            {"case": case["name"], "observation_sha256": sha(raw({key: native[key] for key in keys}))},
        )
    print(f"Verified {len(witnesses['countdown'])} countdown cases", flush=True)
    damage_config, damage_sha = build_config("creature_apply_damage", out)
    damage = impacts.Program(damage_config, integrated=True)
    for health, amount, damage_type, flags, slot, active, player_count in itertools.product(
        (0.0, -1.0, 100.0), (0.0, 1.0), (0, 1, 3, 4, 7), (0, 4), (0, 383), (0, 1), (0, 1),
    ):
        case = {
            "name": f"damage-{health}-{amount}-{damage_type}-{flags}-{slot}-{active}-{player_count}",
            "fpcw": 0x7F,
            "rng_seed": 123,
            "dt": f32(0.016),
            "damage": amount,
            "damage_type": damage_type,
            "players": [{"index": 0, "health": 100}] if player_count else [],
            "creatures": [
                {
                    "index": slot,
                    "active": active,
                    "health": health,
                    "max_health": 100,
                    "size": 32,
                    "flags": flags,
                    "hit_flash": -1,
                    "lifecycle": 16 if health > 0 else 5,
                },
            ],
        }
        native, current = damage_run(damage, True, case), damage_run(damage, False, case)
        keys = ("state", "scalars", "calls", "writes", "rng_state")
        assert all(native[key] == current[key] for key in keys), case["name"]
        timer_bits = struct.unpack_from("<I", native["state"]["creature_pool"], slot * 152 + 56)[0]
        assert timer_bits == bits(0.2)
        witnesses["damage"].append({"input": case, "timer_bits": timer_bits})
        receipts["damage"].append(
            {"case": case["name"], "observation_sha256": sha(raw({key: native[key] for key in keys}))},
        )
    print(f"Verified {len(witnesses['damage'])} damage cases", flush=True)
    damage_source = (damage_config.directory / damage_config.source).read_text()
    old = "    creature_pool[creature_id].hit_flash_timer = 0.2f;"
    assert damage_source.count(old) == 1
    mutated = damage_source.replace(old, "    if (creature_pool[creature_id].active) {\n" + old + "\n    }")
    directory = out / "skip-inactive-flash-refresh"
    directory.mkdir(exist_ok=True)
    (directory / "scratch.cpp").write_text(mutated)
    wrong = impacts.Program(replace(damage_config, directory=directory), integrated=True)
    case = next(row["input"] for row in witnesses["damage"] if not row["input"]["creatures"][0]["active"] and row["input"]["players"])
    native, candidate = damage_run(damage, True, case), damage_run(wrong, False, case)
    assert native["state"] != candidate["state"]
    controls.append({"name": "skip-inactive-flash-refresh", "source_sha256": sha(mutated.encode()), "case": case["name"], "detected": "state"})
    witness_raw = (json.dumps(witnesses, indent=2) + "\n").encode()
    (out / "witnesses.json").write_bytes(witness_raw)
    result = {
        "schema_version": 1,
        "scope": __doc__,
        "unicorn": unicorn.__version__,
        "layout": layout,
        "game_sha256": sha(match.default_image_path().read_bytes()),
        "grim_sha256": sha(match.default_image_path("grim.dll").read_bytes()),
        "sources": {
            "renderer": renderer_sha,
            "update": update_sha,
            "damage": damage_sha,
            "verify": sha(Path(__file__).read_bytes()),
            "frame_runner": sha(Path(frames.__file__).read_bytes()),
            "render_runner": sha(frames.PARENT.read_bytes()),
            "update_runner": sha(Path(updates.__file__).read_bytes()),
            "impact_runner": sha(Path(impacts.__file__).read_bytes()),
            "frame_fixtures": sha((EVIDENCE / "creature-frame-selection-2026-09-11/fixtures.py").read_bytes()),
            "program_loader": sha(updates.ENGINE_PATH.read_bytes()),
            "gameplay_header": sha((match.DEFAULT_MATCH_ROOT / "include/crimsonland_gameplay.h").read_bytes()),
        },
        "candidate_bodies": {"renderer": sha(renderer.body.data), "update": sha(updater.program.body.data), "damage": sha(damage.body.data)},
        "witnesses_sha256": sha(witness_raw),
        "native_color_coverage": sorted(color.coverage),
        "color_ftol_model": {"import_slot": color.ftol_import, "game_converter": color.ftol_start},
        "negative_controls": controls,
        "cases": receipts,
    }
    (out / "results.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
