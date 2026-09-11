"""Execute primary movement with real native vector, creature, and player lookup.

Derived from the particle-impact runner. Unknown control transfers and writes
outside declared observations fail; fixture paths consume no random draws.
"""

import importlib.util
import struct

import capstone
import unicorn
from unicorn import x86_const as x86

from crimson import match

spec = importlib.util.spec_from_file_location(
    "engine",
    match.DEFAULT_MATCH_ROOT / "evidence/plasma-head-alpha-2026-09-10/verify.py",
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Program(m.Program):
    def __init__(self, config, *, integrated=False):
        super().__init__(config)
        manifest = match.load_function_manifest(scope="all")
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.helpers = {}
        helpers = [
            "crt_ftol",
            "vec2_add",
            "vec2_add_inplace",
            "fx_spawn_sprite",
            "creature_find_in_radius",
            "player_find_in_radius",
        ]
        if integrated:
            helpers.extend(("creature_apply_damage", "fx_queue_add_random"))
        self.integrated = integrated
        for name in helpers:
            _, start, end = match.resolve_function(manifest, name)
            self.helpers[name] = (start, {i.address for i in md.disasm(self.image.function_bytes(start, end), start)})


POOLS = {
    "projectile_pool": (96, 64),
    "secondary_projectile_pool": (64, 44),
    "sprite_effect_pool": (384, 44),
    "particle_pool": (128, 56),
    "creature_pool": (385, 152),
    "player_state_table": (2, 864),
}
F = {
    "primary": {
        "active": (0, "B"),
        "angle": (4, "f"),
        "x": (8, "f"),
        "y": (12, "f"),
        "origin_x": (16, "f"),
        "origin_y": (20, "f"),
        "vx": (24, "f"),
        "vy": (28, "f"),
        "type": (32, "i"),
        "life": (36, "f"),
        "speed": (44, "f"),
        "damage": (48, "f"),
        "radius": (52, "f"),
        "travel": (56, "f"),
        "owner": (60, "i"),
    },
    "secondary": {
        "active": (0, "B"),
        "angle": (4, "f"),
        "life": (8, "f"),
        "x": (12, "f"),
        "y": (16, "f"),
        "vx": (20, "f"),
        "vy": (24, "f"),
        "type": (28, "i"),
        "trail": (32, "f"),
        "target": (36, "i"),
    },
    "sprites": {
        "active": (0, "B"),
        "alpha": (16, "f"),
        "rotation": (20, "f"),
        "x": (24, "f"),
        "y": (28, "f"),
        "vx": (32, "f"),
        "vy": (36, "f"),
        "scale": (40, "f"),
    },
    "particles": {
        "active": (0, "B"),
        "render": (1, "B"),
        "x": (4, "f"),
        "y": (8, "f"),
        "vx": (12, "f"),
        "vy": (16, "f"),
        "sx": (20, "f"),
        "sy": (24, "f"),
        "sz": (28, "f"),
        "age": (32, "f"),
        "intensity": (36, "f"),
        "angle": (40, "f"),
        "spin": (44, "f"),
        "style": (48, "B"),
        "target": (52, "i"),
    },
}
CATEGORIES = dict(zip(F, ("projectile_pool", "secondary_projectile_pool", "sprite_effect_pool", "particle_pool")))
F["creatures"] = {
    "active": (0, "B"),
    "state_flag": (8, "B"),
    "lifecycle": (16, "f"),
    "x": (20, "f"),
    "y": (24, "f"),
    "health": (36, "f"),
    "max_health": (40, "f"),
    "size": (52, "f"),
    "r": (60, "f"),
    "g": (64, "f"),
    "b": (68, "f"),
    "a": (72, "f"),
    "type": (108, "i"),
}
F["creatures"].update(vx=(28, "f"), vy=(32, "f"), heading=(44, "f"), hit_flash=(56, "f"), flags=(140, "I"))
CATEGORIES["creatures"] = "creature_pool"
F["players"] = {
    "active": (0, "B"),
    "x": (20, "f"),
    "y": (24, "f"),
    "health": (36, "f"),
    "size": (52, "f"),
    "shield": (792, "f"),
}
CATEGORIES["players"] = "player_state_table"
SCALARS = (
    "config_player_count",
    "projectile_update_tick",
    "shock_chain_links_left",
    "shock_chain_projectile_id",
    "camera_shake_pulses",
    "highscore_record_shots_hit",
    "music_track_extra_0",
    "music_playlist_randomized_latch",
    "fx_queue_random_color_r",
    "fx_queue_random_color_g",
    "fx_queue_random_color_b",
    "fx_queue_random_color_a",
    "fx_queue_random_init_flags",
)


def run(p, native, case):
    u = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    u.mem_map(p.image.image_base, m.page_size(p.image.size_of_image))
    u.mem_write(p.image.image_base, p.image.mapped)
    u.mem_map(m.CODE, p.code_size)
    for a, b in p.patched_sections.items():
        if b:
            u.mem_write(a, b)
    u.mem_map(m.STACK, 0x10000)
    u.mem_write(m.STACK, b"\xa5" * 0x10000)
    u.mem_map(m.STUB, 0x4000)

    def write(name, v, fmt="i"):
        u.mem_write(p.address(name), struct.pack("<" + fmt, v))

    for name, (n, size) in POOLS.items():
        u.mem_write(p.address(name), bytes(n * size))
    for name in SCALARS:
        write(name, 0, "B" if name in ("music_playlist_randomized_latch", "fx_queue_random_init_flags") else "i")
    write("config_player_count", len(case.get("players", [])))
    write("frame_dt", case.get("dt", 0.016), "f")
    write("projectile_update_tick", case.get("tick", 0))
    write("shock_chain_projectile_id", case.get("shock_id", -1))
    write("shock_chain_links_left", case.get("shock_links", 3))
    write("terrain_texture_width", 1024)
    write("terrain_texture_height", 1024)
    write("bonus_freeze_timer", case.get("freeze", 0), "f")
    write("perk_id_ion_gun_master", 1)
    write("perk_id_barrel_greaser", 34 if p.integrated else 2)
    write("perk_id_pyromaniac", 39)
    write("perk_id_uranium_filled_bullets", 28)
    write("perk_id_doctor", 29)
    write("config_violence_disabled", case.get("violence_disabled", 0), "B")
    for category, name in CATEGORIES.items():
        for entry in case.get(category, []):
            index = entry.get("index", 0)
            a = p.address(name) + index * POOLS[name][1]
            assert 0 <= index < POOLS[name][0]
            values = {"active": 1}
            values.update(entry)
            for k, v in values.items():
                if k == "index":
                    continue
                off, fmt = F[category][k]
                u.mem_write(a + off, struct.pack("<" + fmt, v))
    esp = m.STACK + 0xF000
    u.mem_write(esp, struct.pack("<I", m.STOP))
    u.reg_write(x86.UC_X86_REG_ESP, esp)
    u.reg_write(x86.UC_X86_REG_FPCW, case.get("fpcw", 0x7F))
    u.reg_write(x86.UC_X86_REG_FPTAG, 0xFFFF)
    saved = [
        (x86.UC_X86_REG_EBX, 0x11110000),
        (x86.UC_X86_REG_ESI, 0x22220000),
        (x86.UC_X86_REG_EDI, 0x33330000),
        (x86.UC_X86_REG_EBP, 0x44440000),
    ]
    for r, v in saved:
        u.reg_write(r, v)
    start = p.native_start if native else p.candidate_start
    expected = {start + i.offset for i in (p.result.target_disassembly if native else p.result.candidate_disassembly)}
    calls = []
    writes = []
    sites = []
    coverage = set()
    ri = 0
    rng_state = case.get("rng_seed", 0)
    rng_callers = []
    callbacks = {
        p.address(n): n
        for n in (
            "perk_count_get",
            "player_find_in_radius",
            "creatures_apply_radius_damage",
            "crt_rand",
            "fx_queue_add",
            "crt_atexit",
            "creature_apply_damage",
            "fx_queue_add_random",
            "sfx_play_panned",
            "creature_handle_death",
        )
    }

    def hook(uc, a, size, data):
        nonlocal ri, rng_state
        if a in expected:
            coverage.add(a)
            return
        for name, (entry, pcs) in p.helpers.items():
            if a in pcs:
                if a == entry:
                    e = uc.reg_read(x86.UC_X86_REG_ESP)
                    if name == "player_find_in_radius":
                        owner, pos, radius = struct.unpack("<3I", uc.mem_read(e + 4, 12))
                        calls.append([name, owner, list(struct.unpack("<2I", uc.mem_read(pos, 8))), radius])
                    elif name == "vec2_add":
                        dst, delta, mode = struct.unpack("<3I", uc.mem_read(e + 4, 12))
                        calls.append([name, dst, list(struct.unpack("<2I", uc.mem_read(delta, 8))), mode])
                    elif name == "creature_find_in_radius":
                        pos, radius, start = struct.unpack("<3I", uc.mem_read(e + 4, 12))
                        calls.append([name, list(struct.unpack("<2I", uc.mem_read(pos, 8))), radius, start])
                    elif name == "creature_apply_damage":
                        args = list(struct.unpack("<4I", uc.mem_read(e + 4, 16)))
                        args[3] = list(struct.unpack("<2I", uc.mem_read(args[3], 8)))
                        calls.append([name, *args])
                    elif name == "fx_queue_add_random":
                        pos = struct.unpack("<I", uc.mem_read(e + 4, 4))[0]
                        calls.append([name, list(struct.unpack("<2I", uc.mem_read(pos, 8)))])
                    elif name == "fx_spawn_sprite":
                        pos, vel, scale = struct.unpack("<3I", uc.mem_read(e + 4, 12))
                        calls.append(
                            [
                                name,
                                list(struct.unpack("<2I", uc.mem_read(pos, 8))),
                                list(struct.unpack("<2I", uc.mem_read(vel, 8))),
                                scale,
                            ],
                        )
                return
        if a in callbacks:
            name = callbacks[a]
            e = uc.reg_read(x86.UC_X86_REG_ESP)
            ret = struct.unpack("<I", uc.mem_read(e, 4))[0]
            reply = 0

            def arg(n):
                return struct.unpack("<" + str(n) + "I", uc.mem_read(e + 4, n * 4))

            if name == "crt_atexit":
                calls.append([name, *arg(1)])
            elif name == "perk_count_get":
                id = arg(1)[0]
                reply = int(id in case.get("perks", []))
                calls.append([name, id, reply])
            elif name in ("creature_find_in_radius", "player_find_in_radius"):
                args = list(arg(3))
                ix = 0 if name.startswith("creature") else 1
                args[ix] = list(struct.unpack("<2I", uc.mem_read(args[ix], 8)))
                calls.append([name, *args])
                reply = case.get("hit_id", -1) & 0xFFFFFFFF if name.startswith("creature") else 0xFFFFFFFF
            elif name == "creatures_apply_radius_damage":
                args = list(arg(4))
                args[0] = list(struct.unpack("<2I", uc.mem_read(args[0], 8)))
                calls.append([name, *args])
            elif name == "creature_apply_damage":
                args = list(arg(4))
                args[3] = list(struct.unpack("<2I", uc.mem_read(args[3], 8)))
                calls.append([name, *args])
            elif name == "fx_queue_add_random":
                pos = arg(1)[0]
                calls.append([name, list(struct.unpack("<2I", uc.mem_read(pos, 8)))])
            elif name == "sfx_play_panned":
                args = list(arg(3))
                args[1] = list(struct.unpack("<2I", uc.mem_read(args[1], 8)))
                calls.append([name, *args])
            elif name == "creature_handle_death":
                calls.append([name, *arg(2)])
            elif name == "crt_rand":
                if "rng_seed" in case:
                    rng_state = (rng_state * 214013 + 2531011) & 0xFFFFFFFF
                    reply = (rng_state >> 16) & 32767
                else:
                    reply = ((ri + case.get("seed", 1)) * 1103515245 + 12345) % 32768
                ri += 1
                calls.append([name, reply])
                rng_callers.append(ret)
            elif name == "fx_queue_add":
                args = list(arg(6))
                args[1] = list(struct.unpack("<2I", uc.mem_read(args[1], 8)))
                args[5] = list(struct.unpack("<4I", uc.mem_read(args[5], 16)))
                calls.append([name, *args])
            uc.reg_write(x86.UC_X86_REG_EIP, ret)
            uc.reg_write(x86.UC_X86_REG_ESP, e + 4)
            uc.reg_write(x86.UC_X86_REG_EAX, reply)
            uc.reg_write(x86.UC_X86_REG_ECX, 0xDEAD1000)
            uc.reg_write(x86.UC_X86_REG_EDX, 0xDEAD2000)
            uc.reg_write(x86.UC_X86_REG_EFLAGS, 0xAD7)
            return
        raise AssertionError(("unknown", native, hex(a)))

    allowed = [(p.address(name), p.address(name) + n * size) for name, (n, size) in POOLS.items()] + [
        (
            p.address(n),
            p.address(n) + (1 if n in ("music_playlist_randomized_latch", "fx_queue_random_init_flags") else 4),
        )
        for n in SCALARS
    ]

    def onwrite(uc, access, a, size, value, data):
        if m.STACK <= a and a + size <= m.STACK + 0x10000:
            return
        assert any(lo <= a and a + size <= hi for lo, hi in allowed), (hex(a), size)
        writes.append([a, size, value & ((1 << (size * 8)) - 1)])
        sites.append(uc.reg_read(x86.UC_X86_REG_EIP))

    u.hook_add(unicorn.UC_HOOK_CODE, hook)
    u.hook_add(unicorn.UC_HOOK_MEM_WRITE, onwrite)
    u.emu_start(start, m.STOP, count=1000000)
    assert u.reg_read(x86.UC_X86_REG_EIP) == m.STOP
    assert u.reg_read(x86.UC_X86_REG_ESP) == esp + 4
    assert u.reg_read(x86.UC_X86_REG_FPTAG) == 0xFFFF
    assert u.reg_read(x86.UC_X86_REG_FPCW) == case.get("fpcw", 0x7F)
    for r, v in saved:
        assert u.reg_read(r) == v
    return {
        "rng_state": rng_state,
        "rng_callers": rng_callers,
        "state": {name: bytes(u.mem_read(p.address(name), n * size)) for name, (n, size) in POOLS.items()},
        "scalars": {
            n: bytes(
                u.mem_read(
                    p.address(n),
                    1 if n in ("music_playlist_randomized_latch", "fx_queue_random_init_flags") else 4,
                ),
            )
            for n in SCALARS
        },
        "calls": calls,
        "writes": writes,
        "sites": sites,
        "coverage": sorted(a - start for a in coverage),
    }
