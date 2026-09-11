"""Bounded native/candidate creature-update execution with explicit callback models."""

import importlib.util
import math
import struct
from pathlib import Path

import capstone
import unicorn
from unicorn import x86_const as x86

from crimson import match

HERE = Path(__file__).resolve().parent
ENGINE_PATH = match.DEFAULT_MATCH_ROOT / "evidence/plasma-head-alpha-2026-09-10/verify.py"
SPEC = importlib.util.spec_from_file_location("creature_program_loader", ENGINE_PATH)
engine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(engine)
STACK, CODE, STOP = engine.STACK, engine.CODE, engine.STOP
FIELDS = {
    "active": (0, "B"),
    "phase_seed": (4, "i"),
    "state_flag": (8, "B"),
    "collision_flag": (9, "B"),
    "collision_timer": (12, "f"),
    "lifecycle_stage": (16, "f"),
    "pos_x": (20, "f"),
    "pos_y": (24, "f"),
    "vel_x": (28, "f"),
    "vel_y": (32, "f"),
    "health": (36, "f"),
    "max_health": (40, "f"),
    "heading": (44, "f"),
    "target_heading": (48, "f"),
    "size": (52, "f"),
    "hit_flash_timer": (56, "f"),
    "tint_r": (60, "f"),
    "tint_g": (64, "f"),
    "tint_b": (68, "f"),
    "tint_a": (72, "f"),
    "force_target": (76, "B"),
    "target_x": (80, "f"),
    "target_y": (84, "f"),
    "contact_damage": (88, "f"),
    "move_speed": (92, "f"),
    "attack_cooldown": (96, "f"),
    "reward_value": (100, "f"),
    "type_id": (108, "i"),
    "target_player": (112, "b"),
    "link_index": (120, "i"),
    "target_offset_x": (124, "f"),
    "target_offset_y": (128, "f"),
    "orbit_angle": (132, "f"),
    "orbit_radius": (136, "f"),
    "projectile_type": (136, "i"),
    "flags": (140, "i"),
    "ai_mode": (144, "i"),
    "anim_phase": (148, "f"),
}


class Comparison:
    def __init__(self, config):
        self.program = engine.Program(config)
        self.native_helpers = {}
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        manifest = engine.match.load_function_manifest(scope="all")
        for name in ("angle_approach", "vec2_add_inplace", "crt_ftol"):
            _, start, end = engine.match.resolve_function(manifest, name)
            data = self.program.image.function_bytes(start, end)
            self.native_helpers[name] = (start, {i.address for i in md.disasm(data, start)})

    def run(self, native, case):
        p = self.program
        native_helpers = self.native_helpers
        mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        mu.mem_map(p.image.image_base, engine.page_size(p.image.size_of_image))
        mu.mem_write(p.image.image_base, p.image.mapped)
        mu.mem_map(CODE, p.code_size)
        for a, data in p.patched_sections.items():
            if data:
                mu.mem_write(a, data)
        mu.mem_map(STACK, 0x10000)
        mu.mem_write(STACK, bytes([case.get("stack_byte", 0xA5)]) * 0x10000)
        mu.mem_map(engine.STUB, 0x4000)

        def w(name, value, fmt="i"):
            mu.mem_write(p.address(name), struct.pack("<" + fmt, value))

        w("frame_dt", case.get("dt", 0.016), "f")
        w("frame_dt_ms", case.get("dt_ms", 16))
        w("creature_update_tick", case.get("tick", 69))
        w("creature_active_count", 111)
        w("creature_kill_count", 11)
        w("plaguebearer_infection_count", case.get("infection_count", 0))
        w("bonus_spawn_guard", 0, "B")
        w("bonus_freeze_timer", case.get("freeze", 0), "f")
        w("bonus_energizer_timer", case.get("energizer", 0), "f")
        w("config_player_count", case.get("player_count", 1))
        for i, name in enumerate(
            (
                "perk_id_plaguebearer",
                "perk_id_radioactive",
                "perk_id_mr_melee",
                "perk_id_toxic_avenger",
                "perk_id_veins_of_poison",
            ),
            1,
        ):
            w(name, i)
        w("config_violence_disabled", case.get("violence", 1), "B")
        w("cv_bodiesFade", engine.STUB + 0x100, "I")
        mu.mem_write(engine.STUB + 0x10C, struct.pack("<f", case.get("fade", 0)))
        pool = p.address("creature_pool")
        players = p.address("player_state_table")
        slots = p.address("creature_spawn_slot_table")
        mu.mem_write(pool, bytes(384 * 152))
        mu.mem_write(players, bytes(2 * 0x360))
        mu.mem_write(slots, bytes(32 * 24))
        for i in range(6):
            mu.mem_write(p.address("creature_type_table") + 68 * i + 52, struct.pack("<f", case.get("anim_rate", 1.0)))
        for i in range(32):
            mu.mem_write(
                slots + i * 24,
                struct.pack(
                    "<3i2fi",
                    0,
                    case.get("spawn_count", 0),
                    case.get("spawn_limit", 4),
                    0.5,
                    case.get("spawn_timer", 1),
                    3,
                ),
            )
        for i in range(2):
            mu.mem_write(
                players + i * 0x360 + 0x14,
                struct.pack("<2f", *case.get("player_positions", [(300, 400), (310, 410)])[i]),
            )
            mu.mem_write(players + i * 0x360 + 0x24, struct.pack("<f", case.get("player_health", [100, 100])[i]))
            mu.mem_write(players + i * 0x360 + 0x30C, struct.pack("<i", case.get("evil_eyes", -1)))
            mu.mem_write(players + i * 0x360 + 0x320, struct.pack("<i", case.get("auto_target", [0, 0])[i]))
            mu.mem_write(players + i * 0x360 + 0x9, struct.pack("<B", case.get("plague_active", 0)))
            mu.mem_write(players + i * 0x360 + 0x318, struct.pack("<f", case.get("shield", 0)))
            mu.mem_write(players + i * 0x360 + 0xAC, struct.pack("<i", case.get("experience", 23)))
        indices = set()
        for ordinal, creature in enumerate(case.get("creatures", [{}])):
            values = {
                "active": 1,
                "lifecycle_stage": 5,
                "pos_x": 120,
                "pos_y": 230,
                "vel_x": 0.4,
                "vel_y": -0.3,
                "health": 0,
                "max_health": 100,
                "heading": 0.3,
                "size": 40,
                "hit_flash_timer": 0.1,
                "target_player": 0,
                "tint_r": 0.6,
                "tint_g": 0.4,
                "tint_b": 0.8,
                "tint_a": 0.7,
                "contact_damage": 17.5,
                "reward_value": 30.25,
            }
            values.update(creature)
            index = values.pop("index", ordinal)
            assert 0 <= index < 384 and index not in indices
            assert values["target_player"] in (0, 1)
            assert not ("projectile_type" in values and "orbit_radius" in values)
            indices.add(index)
            for name, value in values.items():
                offset, fmt = FIELDS[name]
                mu.mem_write(pool + index * 152 + offset, struct.pack("<" + fmt, value))
        esp = STACK + 0xF000
        mu.mem_write(esp, struct.pack("<I", STOP))
        mu.reg_write(x86.UC_X86_REG_ESP, esp)
        fpcw = case.get("fpcw", 0x37F)
        assert fpcw in (0x37F, 0x7F)
        mu.reg_write(x86.UC_X86_REG_FPCW, fpcw)
        mu.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)
        preserved = (
            (x86.UC_X86_REG_EBX, 0x11110000),
            (x86.UC_X86_REG_ESI, 0x22220000),
            (x86.UC_X86_REG_EDI, 0x33330000),
            (x86.UC_X86_REG_EBP, 0x44440000),
        )
        for reg, value in preserved:
            mu.reg_write(reg, value)
        start = p.native_start if native else p.candidate_start
        expected = {
            start + i.offset for i in (p.result.target_disassembly if native else p.result.candidate_disassembly)
        }
        coverage = set()
        writes = []
        write_sites = []
        model_writes = []
        calls = []
        returns = []
        random_index = 0
        counts = {
            "creature_apply_damage": 4,
            "creature_handle_death": 2,
            "fx_queue_add_random": 1,
            "fx_queue_add_rotated": 5,
            "sfx_play_panned": 3,
            "projectile_spawn": 4,
            "creature_spawn_template": 3,
            "player_take_damage": 2,
            "effect_spawn_burst": 2,
            "effect_spawn_blood_splatter": 3,
            "plaguebearer_spread_infection": 1,
            "crt_rand": 0,
            "D3DXVec2Normalize": 2,
        }
        stubs = {p.address(name): (name, count) for name, count in counts.items()}

        def hook(uc, a, size, data):
            nonlocal random_index
            if a in expected:
                coverage.add(a)
                return
            for name, (entry, pcs) in native_helpers.items():
                if a in pcs:
                    if a == entry:
                        e = uc.reg_read(x86.UC_X86_REG_ESP)
                        if name == "angle_approach":
                            pointer, target, rate = struct.unpack("<3I", uc.mem_read(e + 4, 12))
                            calls.append([name, pointer, target, rate])
                        if name == "vec2_add_inplace":
                            index, pos, delta = struct.unpack("<3I", uc.mem_read(e + 4, 12))
                            calls.append([name, index, pos, list(struct.unpack("<2I", uc.mem_read(delta, 8)))])
                    return
            if a == p.address("perk_count_get"):
                e = uc.reg_read(x86.UC_X86_REG_ESP)
                ret, perk = struct.unpack("<2I", uc.mem_read(e, 8))
                calls.append(["perk_count_get", perk])
                uc.reg_write(x86.UC_X86_REG_EIP, ret)
                uc.reg_write(x86.UC_X86_REG_ESP, e + 4)
                uc.reg_write(x86.UC_X86_REG_EAX, int(perk in case.get("perks", ())))
                uc.reg_write(x86.UC_X86_REG_ECX, 0xDEAD1000)
                uc.reg_write(x86.UC_X86_REG_EDX, 0xDEAD2000)
                uc.reg_write(x86.UC_X86_REG_EFLAGS, 0xAD7)
                return
            if a in stubs:
                name, n = stubs[a]
                e = uc.reg_read(x86.UC_X86_REG_ESP)
                ret = struct.unpack("<I", uc.mem_read(e, 4))[0]
                args = list(struct.unpack("<" + "I" * n, uc.mem_read(e + 4, 4 * n))) if n else []
                observed = args[:]
                reply = 0

                def vector(ptr):
                    return list(struct.unpack("<2I", uc.mem_read(ptr, 8)))

                if name in (
                    "fx_queue_add_random",
                    "effect_spawn_burst",
                    "effect_spawn_blood_splatter",
                    "projectile_spawn",
                ):
                    observed[0] = vector(args[0])
                if name in ("sfx_play_panned", "creature_spawn_template"):
                    observed[1] = vector(args[1])
                if name == "creature_apply_damage":
                    observed[3] = vector(args[3])
                    if case.get("damage_model", False):
                        health_addr = pool + args[0] * 152 + 36
                        health = struct.unpack("<f", uc.mem_read(health_addr, 4))[0]
                        damage = struct.unpack("<f", struct.pack("<I", args[1]))[0]
                        uc.mem_write(health_addr, struct.pack("<f", health - damage))
                        model_writes.append([health_addr, bytes(uc.mem_read(health_addr, 4)).hex()])
                if name == "fx_queue_add_rotated":
                    observed[0] = vector(args[0])
                    observed[1] = list(struct.unpack("<4I", uc.mem_read(args[1], 16)))
                    reply = case.get("queued", 1)
                if name == "D3DXVec2Normalize":
                    assert all(STACK <= ptr <= STACK + 0x10000 - 8 for ptr in args)
                    observed = [vector(args[1])]
                    x, y = struct.unpack("<2f", uc.mem_read(args[1], 8))
                    length = math.sqrt(x * x + y * y)
                    uc.mem_write(args[0], struct.pack("<2f", x / length if length else 0, y / length if length else 0))
                    reply = args[0]
                if name == "crt_rand":
                    reply = ((random_index + case.get("random_seed", 1)) * 1103515245 + 12345) % 32768
                    random_index += 1
                    observed = [reply]
                calls.append([name, *observed])
                returns.append(ret)
                uc.reg_write(x86.UC_X86_REG_EIP, ret)
                uc.reg_write(x86.UC_X86_REG_ESP, e + (12 if name == "D3DXVec2Normalize" else 4))
                uc.reg_write(x86.UC_X86_REG_EAX, reply)
                uc.reg_write(x86.UC_X86_REG_ECX, 0xDEAD1000)
                uc.reg_write(x86.UC_X86_REG_EDX, 0xDEAD2000)
                uc.reg_write(x86.UC_X86_REG_EFLAGS, 0xAD7)
                return
            raise AssertionError(("external", hex(a)))

        def onwrite(uc, access, a, size, value, data):
            if STACK <= a and a + size <= STACK + 0x10000:
                return
            assert any(start <= a and a + size <= end for start, end in allowed_writes), (hex(a), size)
            writes.append([a, size, value & ((1 << (8 * size)) - 1)])
            write_sites.append(uc.reg_read(x86.UC_X86_REG_EIP))

        scalar_sizes = {
            "creature_update_tick": 4,
            "creature_active_count": 4,
            "creature_kill_count": 4,
            "plaguebearer_infection_count": 4,
            "bonus_spawn_guard": 1,
        }
        allowed_writes = [(pool, pool + 384 * 152), (players, players + 2 * 0x360), (slots, slots + 32 * 24)]
        allowed_writes.extend((p.address(name), p.address(name) + size) for name, size in scalar_sizes.items())
        mu.hook_add(unicorn.UC_HOOK_CODE, hook)
        mu.hook_add(unicorn.UC_HOOK_MEM_WRITE, onwrite)
        mu.emu_start(start, STOP, count=500000)
        assert mu.reg_read(x86.UC_X86_REG_EIP) == STOP
        assert mu.reg_read(x86.UC_X86_REG_ESP) == esp + 4
        for reg, value in preserved:
            assert mu.reg_read(reg) == value
        assert mu.reg_read(x86.UC_X86_REG_FPCW) == fpcw
        return {
            "state": bytes(mu.mem_read(pool, 384 * 152)),
            "players": bytes(mu.mem_read(players, 2 * 0x360)),
            "slots": bytes(mu.mem_read(slots, 32 * 24)),
            "scalars": {name: bytes(mu.mem_read(p.address(name), size)).hex() for name, size in scalar_sizes.items()},
            "writes": writes,
            "write_sites": write_sites,
            "model_writes": model_writes,
            "calls": calls,
            "returns": returns,
            "coverage": len(coverage),
            "coverage_offsets": sorted(address - start for address in coverage),
        }
