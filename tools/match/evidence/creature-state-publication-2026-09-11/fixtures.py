"""Deterministic fixture families for the bounded creature-update audit."""

import copy
import itertools
import random
import struct
from dataclasses import replace

from execute import FIELDS, match


def check_layout(config, out):
    directory = out / "layout"
    directory.mkdir(exist_ok=True)
    layout = {
        "sizeof(creature_t)": 152,
        "sizeof(player_state_t)": 864,
        "sizeof(creature_spawn_slot_t)": 24,
        "sizeof(creature_type_t)": 68,
        "sizeof(bonus_spawn_guard)": 1,
        "offsetof(cvar_float_t, value)": 12,
        "offsetof(player_state_t, position)": 20,
        "offsetof(player_state_t, health)": 36,
        "offsetof(player_state_t, plaguebearer_active)": 9,
        "offsetof(player_state_t, evil_eyes_target_creature)": 0x30C,
        "offsetof(player_state_t, auto_target)": 0x320,
        "offsetof(player_state_t, shield_timer)": 0x318,
        "offsetof(player_state_t, experience)": 0xAC,
        "offsetof(creature_type_t, anim_rate)": 52,
    }
    for name, (offset, _fmt) in FIELDS.items():
        field = {"orbit_radius": "orbit_radius.radius", "projectile_type": "orbit_radius.projectile_type"}.get(name, name)
        layout[f"offsetof(creature_t, {field})"] = offset
    for offset, name in enumerate(("owner", "count", "limit", "interval_s", "timer_s", "template_id")):
        layout[f"offsetof(creature_spawn_slot_t, {name})"] = offset * 4
    source = '#include "crimsonland_gameplay.h"\n#include <stddef.h>\nextern "C" {\n'
    source += "unsigned int execution_offsets[] = {" + ", ".join(layout) + "};\n}\n"
    (directory / "scratch.cpp").write_text(source)
    path = match.compile_scratch(replace(config, directory=directory))
    obj = match.parse_coff_object(path.read_bytes())
    symbol = next(row for row in obj.symbols if row.name == "_execution_offsets")
    raw = obj.sections[symbol.section_number - 1].data[symbol.value:symbol.value + 4 * len(layout)]
    actual = struct.unpack("<" + "I" * len(layout), raw)
    assert list(actual) == list(layout.values()), dict(zip(layout, actual, strict=True))
    return layout


def scenarios():
    rng = random.Random(20260911)
    cases = []
    for index in range(1000):
        case = {
            "name": f"mixed-{index}",
            "dt": rng.choice((0.016, 0.033, 0.1, 0.0001)), "freeze": 0,
            "tick": rng.choice((69, 0, 70)), "fade": index % 2,
            "player_count": rng.choice((1, 2)),
            "player_health": rng.choice(([100, 100], [0, 100], [100, 0])),
            "anim_rate": rng.uniform(0.5, 2),
            "perks": rng.choice(([], [1], [2], [3], [4], [5], [1, 2, 3, 4, 5])),
            "spawn_timer": rng.choice((-0.1, 0.1)), "damage_model": index % 2 == 0,
            "energizer": rng.choice((0, 0, 1)), "plague_active": index % 2,
            "queued": index % 2, "violence": index % 2,
            "creatures": [
                {
                    "index": slot, "lifecycle_stage": rng.choice((16, 16, 16, 0.1, 5)),
                    "health": rng.uniform(0, 150), "move_speed": rng.uniform(0.1, 3),
                    "phase_seed": rng.randrange(20), "ai_mode": rng.randrange(9),
                    "target_player": rng.choice((0, 1)),
                    "pos_x": rng.uniform(285, 345), "pos_y": rng.uniform(385, 445),
                    "heading": rng.uniform(-7, 7), "size": rng.uniform(10, 120),
                    "link_index": 0, "orbit_radius": rng.uniform(0, 100), "orbit_angle": rng.uniform(-3, 3),
                    "collision_flag": rng.choice((0, 1)), "collision_timer": rng.choice((-0.1, 0.1)),
                    "flags": rng.choice((0, 1, 2, 4, 0x10, 0x44, 0x80, 0x100)),
                    "attack_cooldown": rng.choice((0, 1)),
                }
                for slot in (0, 3)
            ],
        }
        # The timer/radius and projectile ID share a native union. A ranged
        # variant supplies an integer template ID, rather than float-radius bits.
        for creature in case["creatures"]:
            if creature["flags"] & 0x100:
                del creature["orbit_radius"]
                creature["projectile_type"] = 9
        cases.append(case)
    cases.extend([
        {"name": "empty", "creatures": []},
        {"name": "last-slot-frozen", "freeze": 1, "creatures": [{"index": 383, "health": 100, "lifecycle_stage": 16}]},
        {"name": "all-slots-frozen", "freeze": 1, "creatures": [{"index": index} for index in range(384)]},
    ])
    for lifecycle, freeze, flags in itertools.product((-11, -10, -0.01, 0, 0.001, 0.1, 5, 16), (0, 1), (0, 4, 0x44)):
        cases.append({
            "name": f"lifecycle-{lifecycle}-{freeze}-{flags}", "freeze": freeze,
            "fade": int(flags != 0), "violence": 0, "queued": int(lifecycle != 0.1),
            "creatures": [{"index": 383, "lifecycle_stage": lifecycle, "health": 0, "flags": flags}],
        })
    for mode, radius, health in itertools.product(range(9), (0, 0.001, 90), (0, 100)):
        cases.append({
            "name": f"ai-link-{mode}-{radius}-{health}", "player_count": 2,
            "creatures": [
                {"index": 0, "health": health, "lifecycle_stage": 5},
                {"index": 383, "health": 100, "lifecycle_stage": 16, "ai_mode": mode,
                 "link_index": 0, "orbit_radius": radius, "orbit_angle": 1.3,
                 "target_offset_x": 10, "target_offset_y": -30, "move_speed": 1.2},
            ],
        })
    for timer, dt_ms in itertools.product((-17, -16, -1, 0, 1, 16, 17), (0, 16)):
        cases.append({
            "name": f"link-timer-{timer}-{dt_ms}", "dt_ms": dt_ms,
            "creatures": [{"health": 100, "lifecycle_stage": 16, "ai_mode": 7, "flags": 0x80, "link_index": timer}],
        })
    for distance, size, shield in itertools.product((0, 19.999, 20, 29.999, 30, 64, 64.001, 99.999, 100, 801), (16, 30, 40), (0, 1)):
        cases.append({
            "name": f"contact-{distance}-{size}-{shield}", "shield": shield,
            "player_positions": [(300, 400), (310, 410)], "perks": [1, 2, 3, 4, 5],
            "damage_model": True, "plague_active": 1,
            "creatures": [{"health": 100, "lifecycle_stage": 16, "ai_mode": 2,
                           "pos_x": 300 + distance, "pos_y": 400, "size": size, "move_speed": 0,
                           "flags": 0x100, "projectile_type": 28, "orbit_angle": 0.4}],
        })
    for flag, count, timer in itertools.product((4, 0x44), (0, 4, 5), (-0.001, 0, 0.001)):
        cases.append({
            "name": f"spawn-{flag}-{count}-{timer}", "spawn_count": count, "spawn_timer": timer,
            "creatures": [{"index": 383, "health": 100, "lifecycle_stage": 16, "flags": flag, "link_index": 31}],
        })
    for infection, evil, stack in itertools.product((49, 50, 59, 60), (-1, 0), (0, 0xA5, 0x5A)):
        cases.append({
            "name": f"infection-eyes-{infection}-{evil}-{stack}", "infection_count": infection,
            "evil_eyes": evil, "stack_byte": stack, "perks": [1, 2], "plague_active": 1,
            "creatures": [{"health": 14.9, "lifecycle_stage": 16, "collision_flag": 1,
                           "collision_timer": -0.01, "pos_x": 310, "pos_y": 410}],
        })
    for mode in (0, 1, 4):
        cases.append({
            "name": f"distant-target-{mode}",
            "creatures": [{"health": 100, "lifecycle_stage": 16, "ai_mode": mode,
                           "pos_x": -1000, "pos_y": -1000, "move_speed": 1}],
        })
    for x, y in ((-100, -100), (2000, 2000)):
        cases.append({
            "name": f"spawner-clamp-{x}-{y}",
            "creatures": [{"health": 100, "lifecycle_stage": 16, "flags": 4, "pos_x": x, "pos_y": y}],
        })
    for flags in (0, 4, 0x44):
        cases.append({
            "name": f"animation-wrap-{flags}",
            "creatures": [{"health": 100, "lifecycle_stage": 16, "flags": flags,
                           "move_speed": 1.7, "anim_phase": 94, "size": 40}],
        })
    cases.append({
        "name": "radioactive-lizard-survival", "perks": [2],
        "creatures": [{"health": 1, "type_id": 1, "lifecycle_stage": 16, "collision_timer": -0.1,
                       "pos_x": 350, "pos_y": 400, "ai_mode": 2, "move_speed": 0}],
    })
    for flags, cooldown in itertools.product((0x10, 0x110), (-2, 0, 1)):
        cases.append({
            "name": f"ranged-shock-{flags}-{cooldown}",
            "creatures": [{"health": 100, "lifecycle_stage": 16, "flags": flags,
                           "projectile_type": 28, "orbit_angle": 0.4, "attack_cooldown": cooldown,
                           "pos_x": 450, "pos_y": 400, "ai_mode": 2, "move_speed": 0}],
        })
    return [dict(copy.deepcopy(case), name=f'{case["name"]}-pc{fpcw:03x}', fpcw=fpcw)
            for case in cases for fpcw in (0x37F, 0x7F)]
