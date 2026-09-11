"""Run bounded player-update fixtures with explicit call-boundary models.

The original movement, heading, vector length/subtraction and CRT conversion
helpers execute as machine code. Input, random, effects, sound, allocation,
reload and damage callbacks are modeled; this is not a whole-game proof.
"""

import importlib.util
import math
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
ENGINE = HERE.parent / "plasma-head-alpha-2026-09-10" / "verify.py"
spec = importlib.util.spec_from_file_location("engine", ENGINE)
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
x = e.x86
u = e.unicorn


PLAYER_FLOAT_FIELDS = {
    "death_timer": 16,
    "pos_x": 20,
    "pos_y": 24,
    "health": 36,
    "heading": 44,
    "size": 52,
    "speed_multiplier": 92,
    "move_speed": 104,
    "move_phase": 148,
    "spread_heat": 696,
    "clip_size": 708,
    "ammo": 716,
    "reload_timer": 720,
    "shot_cooldown": 724,
    "reload_timer_max": 728,
    "muzzle_flash_alpha": 764,
    "aim_heading": 768,
    "turn_speed": 772,
    "low_health_timer": 784,
    "speed_bonus_timer": 788,
    "man_bomb_timer": 160,
    "living_fortress_timer": 164,
    "fire_cough_timer": 168,
    "hot_tempered_timer": 156,
    "fire_bullets_timer": 796,
    "alt_clip_size": 736,
    "alt_ammo": 744,
    "alt_reload_timer": 748,
    "alt_shot_cooldown": 752,
    "alt_reload_timer_max": 756,
    "move_target_x": 804,
    "move_target_y": 808,
}


def linked(p):
    for a, b in p.patched_sections.items():
        if a <= p.candidate_start < a + len(b):
            return b[p.candidate_start - a : p.candidate_start - a + len(p.body.data)]
    raise AssertionError()


def execution_data(p, native):
    # All code bytes are immutable for a Program. Keep decoding out of the
    # per-fixture path; each execution still owns fresh memory and registers.
    if not hasattr(p, "_player_update_execution"):
        p._player_update_execution = {}
    if native not in p._player_update_execution:
        md = e.capstone.Cs(e.capstone.CS_ARCH_X86, e.capstone.CS_MODE_32)
        start = p.native_start if native else p.candidate_start
        code = p.image.function_bytes(p.native_start, p.native_end) if native else linked(p)
        expected = {i.address for i in md.disasm(code, start)}
        ftol = p.address("crt_ftol")
        ftol_pcs = set()
        for ins in md.disasm(p.image.function_bytes(ftol, ftol + 128), ftol):
            ftol_pcs.add(ins.address)
            if ins.mnemonic == "ret":
                break
        assert ins.mnemonic == "ret"
        helpers = {}
        helper_pcs = set()
        manifest = e.match.load_function_manifest(scope="all")
        for name in (
            "player_apply_move_with_spawn_avoidance",
            "player_heading_approach_target",
            "vec2_length",
            "vec2_sub",
        ):
            _, a, b = e.match.resolve_function(manifest, name)
            assert a == p.address(name)
            helpers[a] = name
            helper_pcs.update(i.address for i in md.disasm(p.image.function_bytes(a, b), a))
        p._player_update_execution[native] = (start, expected, ftol_pcs, helpers, helper_pcs)
    return p._player_update_execution[native]


def run(p, native, frame):
    assert p.config.function == "player_update"
    assert frame.get("cw", 127) == 127, "This fixture set targets gameplay PC=24"
    assert 0 <= frame.get("weapon", 1) < 64 and 0 <= frame.get("alt_weapon", 2) < 64
    assert -1 <= frame.get("auto_target", 0) < 384
    mu = u.Uc(u.UC_ARCH_X86, u.UC_MODE_32)
    mu.mem_map(p.image.image_base, e.page_size(p.image.size_of_image))
    mu.mem_write(p.image.image_base, p.image.mapped)
    mu.mem_map(e.CODE, p.code_size)
    for a, b in p.patched_sections.items():
        if b:
            mu.mem_write(a, b)
    mu.mem_map(e.STACK, 65536)
    mu.mem_write(e.STACK, b"\xa5" * 65536)
    mu.mem_map(e.STUB, 16384)
    mu.mem_write(e.THIS, struct.pack("<I", e.VTABLE))
    mu.mem_write(e.VTABLE, struct.pack("<80I", *(e.STUB + i * 16 for i in range(80))))

    def w(name, value, fmt="<I"):
        a = p.address(name)
        b = struct.pack(fmt, value)
        mu.mem_write(a, b)

    for name, value, fmt in [
        ("grim_interface_ptr", e.THIS, "<I"),
        ("console_open_flag", frame.get("console", 0), "<B"),
        ("render_overlay_player_index", frame.get("index", 0), "<I"),
        ("time_scale_active", frame.get("time_scale_active", 0), "<B"),
        ("time_scale_factor", frame.get("time_scale_factor", 1), "<f"),
        ("demo_mode_active", frame.get("demo", 0), "<B"),
        ("frame_dt", frame.get("dt", 0.016), "<f"),
        ("frame_dt_ms", 16, "<i"),
        ("ui_mouse_x", frame.get("mouse_x", 322.25), "<f"),
        ("ui_mouse_y", frame.get("mouse_y", 280.75), "<f"),
        ("camera_offset_x", 13.125, "<f"),
        ("camera_offset_y", -21.75, "<f"),
        ("bonus_weapon_power_up_timer", frame.get("powerup", 0), "<f"),
        ("player_spread_damping_gate", frame.get("damping_gate", 0), "<f"),
        ("player_spread_damping_scalar", frame.get("damping", 0.7), "<f"),
        ("terrain_texture_width", 1024, "<i"),
        ("terrain_texture_height", 1024, "<i"),
        ("config_player_count", 1, "<i"),
        ("config_key_reload", 90, "<i"),
    ]:
        w(name, value, fmt)
    for i, name in enumerate(
        (
            "player_alt_move_key_forward",
            "player_alt_move_key_backward",
            "player_alt_turn_key_left",
            "player_alt_turn_key_right",
        ),
        200,
    ):
        w(name, i)
    index = frame.get("index", 0)
    assert index in (0, 1)
    for name, value in [
        ("config_movement_schemes", frame.get("movement", 0)),
        ("config_aim_schemes", frame.get("aim", 0)),
    ]:
        mu.mem_write(p.address(name), struct.pack("<2i", value, value))
    mu.mem_write(p.address("creature_spawn_slot_table"), bytes(32 * 24))
    players = p.address("player_state_table")
    mu.mem_write(players, bytes(864 * 2))
    aim = p.address("player_aim_screen_x")
    mu.mem_write(aim, struct.pack("<4f", 77, 88, 99, 111))
    offsets = PLAYER_FLOAT_FIELDS
    defaults = {
        "death_timer": 5,
        "pos_x": 111.25,
        "pos_y": 208.5,
        "health": 100,
        "heading": 0.5,
        "size": 48,
        "speed_multiplier": 1,
        "move_speed": 0.7,
        "move_phase": 4,
        "spread_heat": 0.2,
        "clip_size": 10,
        "ammo": 7,
        "shot_cooldown": 0.1,
        "low_health_timer": 100,
    }
    for name, offset in offsets.items():
        mu.mem_write(players + index * 864 + offset, struct.pack("<f", frame.get(name, defaults.get(name, 0))))
    mu.mem_write(players + index * 864 + 704, struct.pack("<i", frame.get("weapon", 1)))
    w("player_alt_weapon_swap_cooldown_ms", frame.get("swap_cooldown", 0), "<i")
    mu.mem_write(players + index * 864 + 732, struct.pack("<i", frame.get("alt_weapon", 2)))
    for off, name in ((712, "reload_active"), (740, "alt_reload_active")):
        mu.mem_write(players + index * 864 + off, bytes([frame.get(name, 0)]))
    mu.mem_write(players + index * 864 + 172, struct.pack("<i", frame.get("experience", 0)))
    mu.mem_write(players + index * 864 + 80, struct.pack("<2f", *frame.get("aim_position", (300, 400))))
    mu.mem_write(players + index * 864 + 812, struct.pack("<13i", *range(100, 113)))
    perk_names = [
        "man_bomb",
        "living_fortress",
        "fire_caugh",
        "hot_tempered",
        "sharpshooter",
        "anxious_loader",
        "stationary_reloader",
        "angry_reloader",
        "alternate_weapon",
        "regression_bullets",
        "ammunition_within",
        "long_distance_runner",
        "fastshot",
    ]
    for i, name in enumerate(perk_names, 1):
        w("perk_id_" + name, i)
        for idx in (0, 1):
            mu.mem_write(players + idx * 864 + 184 + 4 * i, struct.pack("<i", frame.get("perks", {}).get(name, 0)))
    for name in (
        "perk_man_bomb_trigger_interval_s",
        "perk_fire_cough_trigger_interval_s",
        "perk_hot_tempered_trigger_interval_s",
    ):
        w(name, frame.get(name, 4), "<f")
    w("cv_friendlyFire", e.STUB + 8192)
    mu.mem_write(e.STUB + 8204, struct.pack("<f", frame.get("friendly_fire", 0)))
    for name, value in (
        ("bonus_reflex_boost_timer", frame.get("reflex", 0)),
        ("fire_bullets_fallback_shot_cooldown", 0.1),
        ("fire_bullets_fallback_spread_heat", 0.2),
    ):
        w(name, value, "<f")
    pool_sizes = {
        "projectile_pool": 96 * 64,
        "sprite_effect_pool": 64 * 44,
        "particle_pool": 128 * 56,
        "effect_template": 60,
    }
    for name, n in pool_sizes.items():
        mu.mem_write(p.address(name), bytes(n))
    for wid in range(64):
        wa = p.address("weapon_table") + wid * 124
        mu.mem_write(wa - 4, struct.pack("<i", frame.get("ammo_class", 1)))
        for off, val, fmt in (
            (72, 0.2, "<f"),
            (76, 1.5, "<f"),
            (80, 0.12, "<f"),
            (88, 11, "<i"),
            (92, 2, "<i"),
            (96, 22, "<i"),
            (104, frame.get("weapon_flags", 0), "<B"),
            (116, frame.get("pellets", 1), "<i"),
        ):
            mu.mem_write(wa + off, struct.pack(fmt, val))
    w("cv_padAimDistMul", e.STUB + 8224)
    mu.mem_write(e.STUB + 8236, struct.pack("<f", frame.get("pad_aim_distance", 150)))
    creatures = p.address("creature_pool")
    mu.mem_write(creatures, bytes(384 * 152))
    for row in frame.get("creatures", []):
        ci = row["index"]
        assert 0 <= ci < 384
        mu.mem_write(creatures + ci * 152, bytes([row.get("active", 1)]))
        for off, val in ((20, row["x"]), (24, row["y"]), (36, row.get("health", 100)), (52, row.get("size", 40))):
            mu.mem_write(creatures + ci * 152 + off, struct.pack("<f", val))
    for si, ci in enumerate(frame.get("spawn_owners", [])):
        assert si < 32 and ci in [row["index"] for row in frame.get("creatures", [])]
        mu.mem_write(p.address("creature_spawn_slot_table") + si * 24, struct.pack("<I", creatures + ci * 152))
    mu.mem_write(players + index * 864 + 800, struct.pack("<i", frame.get("auto_target", 0)))
    axes = e.STUB + 132 // 4 * 16
    axis_value = e.STUB + 10240
    mu.mem_write(axes, b"\xd9\x05" + struct.pack("<I", axis_value) + b"\xc2\x04\x00")
    normalize = p.address("D3DXVec2Normalize")
    esp = e.STACK + 61440
    mu.mem_write(esp, struct.pack("<I", e.STOP))
    mu.reg_write(x.UC_X86_REG_ESP, esp)
    cw = frame.get("cw", 127)
    mu.reg_write(x.UC_X86_REG_FPCW, cw)
    mu.reg_write(x.UC_X86_REG_FPTAG, 65535)
    saved = [
        (x.UC_X86_REG_EBX, 286326784),
        (x.UC_X86_REG_ESI, 572653568),
        (x.UC_X86_REG_EDI, 858980352),
        (x.UC_X86_REG_EBP, 1145307136),
    ]
    for r, v in saved:
        mu.reg_write(r, v)
    start, expected, ftol_pcs, helpers, helper_pcs = execution_data(p, native)
    perk = p.address("perk_count_get")
    key = e.STUB + 128 // 4 * 16
    keydown = e.STUB + 68 // 4 * 16
    externals = {
        p.address(name): (name, argc, ptrs)
        for name, argc, ptrs in [
            ("projectile_spawn", 4, [0]),
            ("fx_spawn_sprite", 3, [0, 1]),
            ("sfx_play_panned", 3, [1]),
            ("effect_spawn_blood_splatter", 3, [0]),
            ("fx_spawn_particle", 4, [0, 2]),
            ("fx_spawn_particle_slow", 3, [0, 2]),
            ("fx_spawn_secondary_projectile", 3, [0]),
            ("effect_spawn", 2, [1]),
            ("player_start_reload", 0, []),
            ("player_take_damage", 2, []),
            ("input_primary_just_pressed", 0, []),
            ("input_aim_pov_left_active", 0, []),
            ("input_aim_pov_right_active", 0, []),
        ]
    }
    rand = p.address("crt_rand")
    rand_state = frame.get("seed", 12345)
    allocations = {}
    calls = []
    writes = []
    coverage = set()
    sites = []

    def vector_words(uc, ptr):
        assert e.STACK <= ptr <= e.STACK + 65536 - 8 or players <= ptr <= players + 2 * 864 - 8, hex(ptr)
        return list(struct.unpack("<2I", uc.mem_read(ptr, 8)))

    def hook(uc, a, size, data):
        nonlocal rand_state
        if a in expected:
            coverage.add(a)
            return
        if a in helpers:
            sp = uc.reg_read(x.UC_X86_REG_ESP)
            if helpers[a] == "player_apply_move_with_spawn_avoidance":
                i, pos, delta = struct.unpack("<3I", uc.mem_read(sp + 4, 12))
                assert i == index and pos == players + index * 864 + 20
                assert e.STACK <= delta <= e.STACK + 65536 - 8
                calls.append(
                    [
                        "move",
                        i,
                        *struct.unpack("<2I", uc.mem_read(pos, 8)),
                        *struct.unpack("<2I", uc.mem_read(delta, 8)),
                    ],
                )
            elif helpers[a] == "player_heading_approach_target":
                calls.append(["heading", struct.unpack("<I", uc.mem_read(sp + 4, 4))[0]])
            elif helpers[a] == "vec2_length":
                ptr = struct.unpack("<I", uc.mem_read(sp + 4, 4))[0]
                calls.append(["length", *struct.unpack("<2I", uc.mem_read(ptr, 8))])
            else:
                dst, rhs = struct.unpack("<2I", uc.mem_read(sp + 4, 8))
                this = uc.reg_read(x.UC_X86_REG_ECX)
                calls.append(
                    [
                        "vec2_sub",
                        *struct.unpack("<2I", uc.mem_read(this, 8)),
                        *struct.unpack("<2I", uc.mem_read(rhs, 8)),
                    ],
                )
        if a in ftol_pcs or a in helper_pcs or a == axes + 6:
            return
        sp = uc.reg_read(x.UC_X86_REG_ESP)
        ret, arg = struct.unpack("<2I", uc.mem_read(sp, 8))
        if a == axes:
            assert uc.reg_read(x.UC_X86_REG_ECX) == e.THIS and arg in range(109, 113)
            value = frame.get("axes", [0.4, 0.7, 0.6, -0.3])[arg - 109]
            raw = struct.pack("<f", value)
            uc.mem_write(axis_value, raw)
            calls.append(["axis", arg, struct.unpack("<I", raw)[0]])
            uc.reg_write(x.UC_X86_REG_EAX, 0)
            uc.reg_write(x.UC_X86_REG_ECX, 3735883776)
            uc.reg_write(x.UC_X86_REG_EDX, 3735887872)
            uc.reg_write(x.UC_X86_REG_EFLAGS, 2775)
            return
        if a == normalize:
            dst, src = struct.unpack("<2I", uc.mem_read(sp + 4, 8))
            assert e.STACK <= src <= e.STACK + 65536 - 8 and e.STACK <= dst <= e.STACK + 65536 - 8
            raw = bytes(uc.mem_read(src, 8))
            vx, vy = struct.unpack("<2f", raw)
            length = math.sqrt(vx * vx + vy * vy)
            calls.append(["normalize", *struct.unpack("<2I", raw)])
            uc.mem_write(dst, struct.pack("<2f", vx / length if length else 0, vy / length if length else 0))
            uc.reg_write(x.UC_X86_REG_EAX, dst)
            uc.reg_write(x.UC_X86_REG_ECX, 3735883776)
            uc.reg_write(x.UC_X86_REG_EDX, 3735887872)
            uc.reg_write(x.UC_X86_REG_EFLAGS, 2775)
            uc.reg_write(x.UC_X86_REG_ESP, sp + 12)
            uc.reg_write(x.UC_X86_REG_EIP, ret)
            return
        if a == rand or a in externals:
            result = 0
            if a == rand:
                rand_state = rand_state * 214013 + 2531011 & 4294967295
                result = rand_state >> 16 & 32767
                calls.append(["rand", result])
            else:
                name, argc, ptrs = externals[a]
                args = list(struct.unpack("<" + "I" * argc, uc.mem_read(sp + 4, 4 * argc))) if argc else []
                for j in ptrs:
                    args[j] = vector_words(uc, args[j])
                if name == "effect_spawn":
                    args.append(bytes(uc.mem_read(p.address("effect_template"), 60)).hex())
                calls.append([name, args])
                if name in ("input_primary_just_pressed", "input_aim_pov_left_active", "input_aim_pov_right_active"):
                    result = int(frame.get(name, False))
                if name in (
                    "projectile_spawn",
                    "fx_spawn_sprite",
                    "fx_spawn_particle",
                    "fx_spawn_particle_slow",
                    "fx_spawn_secondary_projectile",
                ):
                    result = allocations.get(name, 0)
                    allocations[name] = result + 1
                    assert result < 64
            uc.reg_write(x.UC_X86_REG_EAX, result)
            uc.reg_write(x.UC_X86_REG_ECX, 3735883776)
            uc.reg_write(x.UC_X86_REG_EDX, 3735887872)
            uc.reg_write(x.UC_X86_REG_EFLAGS, 2775)
            uc.reg_write(x.UC_X86_REG_ESP, sp + 4)
            uc.reg_write(x.UC_X86_REG_EIP, ret)
            return
        if a in (perk, key, keydown):
            if a == perk:
                assert 1 <= arg <= len(perk_names)
            if a in (key, keydown):
                assert uc.reg_read(x.UC_X86_REG_ECX) == e.THIS
            calls.append(["perk" if a == perk else "key" if a == key else "keydown", arg])
            sites.append(hex(ret))
            uc.reg_write(
                x.UC_X86_REG_EAX,
                int(arg in frame.get("keys", []))
                if a in (key, keydown)
                else frame.get("perks", {}).get(perk_names[arg - 1], 0),
            )
            uc.reg_write(x.UC_X86_REG_ECX, 3735883776)
            uc.reg_write(x.UC_X86_REG_EDX, 3735887872)
            uc.reg_write(x.UC_X86_REG_EFLAGS, 2775)
            uc.reg_write(x.UC_X86_REG_ESP, sp + (8 if a in (key, keydown) else 4))
            uc.reg_write(x.UC_X86_REG_EIP, ret)
            return
        raise AssertionError(("unknown", hex(a), hex(ret)))

    regions = [("players", players, 864 * 2), ("aim_screen", aim, 16)] + [
        (name, p.address(name), 4) for name in ("frame_dt", "player_spread_damping_scalar", "player_heading_turn_delta")
    ]
    regions.extend(((name, p.address(name), n) for name, n in pool_sizes.items()))
    regions.extend(
        (
            (name, p.address(name), n)
            for name, n in [
                ("survival_reward_fire_seen", 1),
                ("bonus_spawn_guard", 1),
                ("perk_man_bomb_trigger_interval_s", 4),
                ("perk_fire_cough_trigger_interval_s", 4),
                ("perk_hot_tempered_trigger_interval_s", 4),
                ("player_alt_weapon_swap_cooldown_ms", 4),
            ]
        ),
    )
    readonly = [
        ("creatures", creatures, 384 * 152),
        ("spawn_slots", p.address("creature_spawn_slot_table"), 32 * 24),
        ("weapon_rows", p.address("weapon_table") - 4, 64 * 124),
    ]
    readonly_before = {name: bytes(mu.mem_read(a, n)) for name, a, n in readonly}

    def onwrite(uc, access, a, n, v, data):
        if e.STACK <= a and a + n <= e.STACK + 65536:
            return
        assert any((base <= a and a + n <= base + length for name, base, length in regions)), ("write", hex(a), n, v)
        writes.append([a, n, v & (1 << 8 * n) - 1])

    mu.hook_add(u.UC_HOOK_CODE, hook)
    mu.hook_add(u.UC_HOOK_MEM_WRITE, onwrite)
    mu.emu_start(start, e.STOP, count=100000)
    assert mu.reg_read(x.UC_X86_REG_EIP) == e.STOP
    assert mu.reg_read(x.UC_X86_REG_ESP) == esp + 4
    assert mu.reg_read(x.UC_X86_REG_FPCW) == cw
    assert mu.reg_read(x.UC_X86_REG_FPTAG) == 65535
    for r, v in saved:
        assert mu.reg_read(r) == v
    for name, a, n in readonly:
        assert bytes(mu.mem_read(a, n)) == readonly_before[name], name
    state = {name: bytes(mu.mem_read(a, n)).hex() for name, a, n in regions}
    return {
        "calls": calls,
        "state": state,
        "writes": writes,
        "coverage": sorted(a - start for a in coverage),
        "sites": sites,
    }
