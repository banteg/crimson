"""Deterministic, finite player-update inputs; no engine calls or expected outputs."""

import random
import struct


def movement_scenarios():
    rng = random.Random(2026091115)
    for i in range(300):
        f = {
            "index": i % 2,
            "movement": rng.choice([0, 1, 2]),
            "keys": rng.sample([100, 101, 102, 103, 200, 201, 202, 203], rng.randrange(5)),
            "dt": rng.choice([0.001, 0.016, 0.033, 0.1, 0.3]),
            "time_scale_active": i % 3 == 0,
            "time_scale_factor": rng.uniform(0.1, 2),
            "powerup": rng.choice([0, 1]),
            "damping_gate": rng.choice([0, 1]),
            "damping": rng.uniform(0.29, 1.01),
            "pos_x": rng.uniform(-30, 1060),
            "pos_y": rng.uniform(-30, 1060),
            "heading": rng.uniform(-8, 8),
            "move_phase": rng.uniform(-30, 40),
            "move_speed": rng.uniform(0, 3),
            "turn_speed": rng.uniform(0, 9),
            "speed_bonus_timer": rng.choice([0, 1]),
            "speed_multiplier": rng.uniform(0.3, 2),
            "muzzle_flash_alpha": rng.uniform(-0.1, 1.5),
            "shot_cooldown": rng.uniform(-0.1, 1),
            "reload_timer": rng.uniform(-0.1, 1),
            "spread_heat": rng.uniform(0, 0.5),
            "mouse_x": rng.uniform(0, 500),
            "mouse_y": rng.uniform(0, 500),
            "weapon": rng.choice([1, 7]),
        }
        yield {"name": f"movement-{i}", "frame": f}


def fire_scenarios():
    rng = random.Random(2026091115)
    for i in range(600):
        f = {
            "index": i % 2,
            "movement": rng.choice([0, 1, 2]),
            "keys": rng.sample([100, 101, 102, 103, 200, 201, 202, 203], rng.randrange(5)),
            "dt": rng.choice([0.001, 0.016, 0.033, 0.1, 0.3]),
            "time_scale_active": i % 3 == 0,
            "time_scale_factor": rng.uniform(0.1, 2),
            "powerup": rng.choice([0, 1]),
            "damping_gate": rng.choice([0, 1]),
            "damping": rng.uniform(0.29, 1.01),
            "pos_x": rng.uniform(-30, 1060),
            "pos_y": rng.uniform(-30, 1060),
            "heading": rng.uniform(-8, 8),
            "move_phase": rng.uniform(-30, 40),
            "move_speed": rng.uniform(0, 3),
            "turn_speed": rng.uniform(0, 9),
            "speed_bonus_timer": rng.choice([0, 1]),
            "speed_multiplier": rng.uniform(0.3, 2),
            "muzzle_flash_alpha": rng.uniform(-0.1, 1.5),
            "shot_cooldown": rng.uniform(-0.1, 1),
            "reload_timer": rng.uniform(-0.1, 1),
            "spread_heat": rng.uniform(0, 0.5),
            "mouse_x": rng.uniform(0, 500),
            "mouse_y": rng.uniform(0, 500),
            "weapon": rng.randrange(1, 54),
            "weapon_flags": rng.randrange(2),
            "pellets": rng.randrange(1, 15),
            "friendly_fire": rng.randrange(2),
            "seed": rng.randrange(1 << 31),
        }
        f["keys"] += [104]
        f["shot_cooldown"] = 0
        f["reload_timer"] = 0
        f["fire_bullets_timer"] = rng.choice([0, 0, 1])
        yield {"name": f"fire-{i}", "frame": f}


def perks_scenarios():
    rng = random.Random(2026091115)
    for i in range(900):
        f = {
            "index": i % 2,
            "movement": rng.choice([0, 1, 2]),
            "keys": rng.sample([100, 101, 102, 103, 200, 201, 202, 203], rng.randrange(5)),
            "dt": rng.choice([0.001, 0.016, 0.033, 0.1, 0.3]),
            "time_scale_active": i % 3 == 0,
            "time_scale_factor": rng.uniform(0.1, 2),
            "powerup": rng.choice([0, 1]),
            "damping_gate": rng.choice([0, 1]),
            "damping": rng.uniform(0.29, 1.01),
            "pos_x": rng.uniform(-30, 1060),
            "pos_y": rng.uniform(-30, 1060),
            "heading": rng.uniform(-8, 8),
            "move_phase": rng.uniform(-30, 40),
            "move_speed": rng.uniform(0, 3),
            "turn_speed": rng.uniform(0, 9),
            "speed_bonus_timer": rng.choice([0, 1]),
            "speed_multiplier": rng.uniform(0.3, 2),
            "muzzle_flash_alpha": rng.uniform(-0.1, 1.5),
            "shot_cooldown": rng.uniform(-0.1, 1),
            "reload_timer": rng.uniform(-0.1, 1),
            "spread_heat": rng.uniform(0, 0.5),
            "mouse_x": rng.uniform(0, 500),
            "mouse_y": rng.uniform(0, 500),
            "weapon": rng.randrange(1, 54),
            "weapon_flags": rng.randrange(2),
            "pellets": rng.randrange(1, 15),
            "friendly_fire": rng.randrange(2),
            "seed": rng.randrange(1 << 31),
        }
        f["keys"] += [104]
        f["shot_cooldown"] = 0
        f["reload_timer"] = rng.choice([0, 0, 0.3, 0.6])
        names = [
            "man_bomb",
            "living_fortress",
            "fire_caugh",
            "hot_tempered",
            "sharpshooter",
            "stationary_reloader",
            "angry_reloader",
            "anxious_loader",
            "alternate_weapon",
            "long_distance_runner",
            "fastshot",
            "regression_bullets",
            "ammunition_within",
        ]
        f["perks"] = {name: 1 for name in rng.sample(names, rng.randrange(1, 7))}
        f["reload_timer_max"] = 1
        f["keys"] += rng.choice([[], [90]])
        f["alt_weapon"] = rng.randrange(1, 54)
        f["alt_ammo"] = rng.uniform(0, 10)
        f["alt_reload_timer"] = rng.choice([0, 0.3])
        f["alt_shot_cooldown"] = rng.choice([0, 0.3])
        f["swap_cooldown"] = rng.choice([0, 8, 100])
        f["input_primary_just_pressed"] = bool(rng.randrange(2))
        f["experience"] = 100
        f["ammo_class"] = rng.choice([1, 2])
        for timer in ("man_bomb_timer", "living_fortress_timer", "fire_cough_timer", "hot_tempered_timer"):
            f[timer] = rng.uniform(0, 7)
        f["low_health_timer"] = rng.choice([100, -0.01, 0.1])
        f["health"] = rng.choice([10, 19, 20, 100])
        f["fire_bullets_timer"] = rng.choice([0, 0, 1])
        yield {"name": f"perks-{i}", "frame": f}


def aim_scenarios():
    rng = random.Random(2026091115)
    for i in range(600):
        f = {
            "index": i % 2,
            "movement": rng.randrange(6),
            "aim": rng.randrange(6),
            "keys": rng.sample([100, 101, 102, 103, 200, 201, 202, 203], rng.randrange(5)),
            "dt": rng.choice([0.001, 0.016, 0.033, 0.1, 0.3]),
            "time_scale_active": i % 3 == 0,
            "time_scale_factor": rng.uniform(0.1, 2),
            "powerup": rng.choice([0, 1]),
            "damping_gate": rng.choice([0, 1]),
            "damping": rng.uniform(0.29, 1.01),
            "pos_x": rng.uniform(-30, 1060),
            "pos_y": rng.uniform(-30, 1060),
            "heading": rng.uniform(-8, 8),
            "move_phase": rng.uniform(-30, 40),
            "move_speed": rng.uniform(0, 3),
            "turn_speed": rng.uniform(0, 9),
            "speed_bonus_timer": rng.choice([0, 1]),
            "speed_multiplier": rng.uniform(0.3, 2),
            "muzzle_flash_alpha": rng.uniform(-0.1, 1.5),
            "shot_cooldown": rng.uniform(-0.1, 1),
            "reload_timer": rng.uniform(-0.1, 1),
            "spread_heat": rng.uniform(0, 0.5),
            "mouse_x": rng.uniform(0, 500),
            "mouse_y": rng.uniform(0, 500),
            "weapon": rng.randrange(1, 54),
            "weapon_flags": rng.randrange(2),
            "pellets": rng.randrange(1, 15),
            "friendly_fire": rng.randrange(2),
            "seed": rng.randrange(1 << 31),
        }
        f["keys"] += [104]
        f["shot_cooldown"] = 0
        f["reload_timer"] = 0
        f["fire_bullets_timer"] = rng.choice([0, 0, 1])
        f["axes"] = [rng.choice([0, rng.uniform(-2, 2)]) for _ in range(4)]
        f["move_target_x"] = rng.choice([-1, rng.uniform(0, 1024)])
        f["move_target_y"] = rng.uniform(0, 1024)
        f["demo"] = int(i % 11 == 0)
        f["creatures"] = [
            {
                "index": ci,
                "x": rng.uniform(0, 1024),
                "y": rng.uniform(0, 1024),
                "health": rng.choice([0, 1, 100]),
                "active": rng.randrange(2),
            }
            for ci in [0, 1, 2, 30, 31, 32, 382, 383]
        ]
        f["auto_target"] = rng.choice([-1, 0, 1, 32, 383])
        f["spawn_owners"] = rng.choice([[], [0], [1, 383]])
        f["aim_position"] = [rng.uniform(0, 1024), rng.uniform(0, 1024)]
        yield {"name": f"aim-{i}", "frame": f}


def f32(value):
    return struct.unpack("<f", struct.pack("<f", value))[0]


def point_scenarios():
    rng = random.Random(2026091116)
    cases = []
    for x, y in [(0, 0), (100, 100), (111.25, 208.5), (-30, 40), (1024, 1024)]:
        for heading in [0, -0.0, f32(1.5707964), f32(3.1415927), f32(4.712389), f32(6.2831855), -0.5, 0.5, 1.3, -1.3]:
            cases.append((f32(x), f32(y), f32(heading)))
    for _ in range(1000):
        cases.append((f32(rng.uniform(-100, 1100)), f32(rng.uniform(-100, 1100)), f32(rng.uniform(-30, 30))))
    for i, (px, py, heading) in enumerate(cases):
        yield {
            "name": f"point-{i}",
            "frame": {
                "aim": 2,
                "movement": 0,
                "dt": 0,
                "pos_x": px,
                "pos_y": py,
                "aim_heading": heading,
                "shot_cooldown": 1,
            },
        }


def scenarios():
    for index in (0, 1):
        for console in (0, 1):
            for health in (-1, 0, 100):
                yield {
                    "name": f"entry-{index}-{console}-{health}",
                    "frame": {"index": index, "console": console, "health": health},
                }
    for movement in range(6):
        for aim in range(6):
            yield {
                "name": f"mode-{movement}-{aim}",
                "frame": {"movement": movement, "aim": aim, "creatures": [{"index": 0, "x": 400, "y": 500}]},
            }
    yield from movement_scenarios()
    yield from fire_scenarios()
    yield from perks_scenarios()
    yield from aim_scenarios()
    yield from point_scenarios()
    yield from turn_scenarios()


def turn_scenarios():
    rng = random.Random(2026091117)
    for i in range(240):
        scheme = 1 + i % 2
        left = bool(i % 3)
        right = bool((i // 3) % 3)
        heading = f32(rng.uniform(-7, 7))
        dt = f32(rng.choice([0.001, 0.016, 0.033, 0.1, 0.3]))
        px = f32(rng.uniform(0, 1024))
        py = f32(rng.uniform(0, 1024))
        yield {
            "name": f"turn-{i}",
            "frame": {
                "aim": scheme,
                "movement": 2,
                "dt": dt,
                "pos_x": px,
                "pos_y": py,
                "aim_heading": heading,
                "move_speed": 0,
                "shot_cooldown": 1,
                "keys": ([107] if left and scheme == 1 else []) + ([108] if right and scheme == 1 else []),
                "input_aim_pov_left_active": left,
                "input_aim_pov_right_active": right,
            },
        }
