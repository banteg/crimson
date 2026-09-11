"""Observe real primary impacts through the Python world and presentation pipeline."""

import struct
from unittest.mock import patch

from crimson.effects import EffectPool, FxQueue
from crimson.game_modes import GameMode
from crimson.math_parity import x87_pc24_mul, x87_pc24_sub
from crimson.owner_ref import OwnerRef
from crimson.projectiles.runtime import PrimaryStepCtx, ProjectileUpdateOptions
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState, _WorldStepRuntime
from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand


def bits(x):
    return struct.unpack("<I", struct.pack("<f", x))[0]


def observe(case):
    world = WorldState.build(world_size=1024.0, demo_mode_active=True, hardcore=False, quest_fail_retry_count=0)
    state = world.state
    state.bonuses.freeze = case.get("freeze", 0.0)
    rng = RecordingCrand(Crand(case["rng_seed"]))
    state.rng = rng
    world.players.append(PlayerState(index=0, pos=Vec2()))
    for perk in case.get("perks", []):
        world.players[0].perk_counts[perk] = 1
    item = case["primary"][0]
    projectile = state.projectiles.entries[item["index"]]
    projectile.active = True
    projectile.angle = item["angle"]
    projectile.pos = Vec2(item["x"], item["y"])
    projectile.origin = Vec2(item["origin_x"], item["origin_y"])
    projectile.type_id = ProjectileTemplateId(item["type"])
    projectile.life_timer = item["life"]
    projectile.speed_scale = item["speed"]
    projectile.damage_pool = item["damage"]
    projectile.hit_radius = item["radius"]
    projectile.travel_budget = item["travel"]
    projectile.owner = OwnerRef.from_legacy(item["owner"])
    target = case["creatures"][0]
    creature = world.creatures.entries[target["index"]]
    creature.active = True
    creature.pos = Vec2(target["x"], target["y"])
    creature.hp = target["health"]
    creature.max_hp = target["max_health"]
    creature.size = target["size"]
    creature.lifecycle_stage = target["lifecycle"]
    creature.tint = RGBA(0, 0, 0, 0)
    runtime = _WorldStepRuntime(
        world=world,
        dt=case["dt"],
        world_size=1024.0,
        detail_preset=5,
        violence_disabled=1,
        fx_queue=FxQueue(),
        game_mode=GameMode.SURVIVAL,
        hit_audio_game_tune_started=True,
        deaths=[],
        sfx=[],
    )
    runtime.violence_disabled = case.get("violence_disabled", 0)
    runtime.fx_queue.violence_disabled = runtime.violence_disabled
    random_positions = []
    splatters = []
    damage_calls = []
    add_random = FxQueue.add_random

    def record_random(self, *, pos, rng):
        random_positions.append([bits(pos.x), bits(pos.y)])
        return add_random(self, pos=pos, rng=rng)

    spawn_blood = EffectPool.spawn_blood_splatter

    def record_blood(self, **kwargs):
        splatters.append([[bits(kwargs["pos"].x), bits(kwargs["pos"].y)], bits(kwargs["angle"]), bits(kwargs["age"])])
        return spawn_blood(self, **kwargs)

    apply_damage = _WorldStepRuntime.apply_creature_damage

    def record_damage(self, creature_index, damage, damage_type, impulse, owner):
        damage_calls.append([creature_index, bits(damage), damage_type, [bits(impulse.x), bits(impulse.y)]])
        return apply_damage(self, creature_index, damage, damage_type, impulse, owner)

    with (
        patch.object(FxQueue, "add_random", record_random),
        patch.object(EffectPool, "spawn_blood_splatter", record_blood),
        patch.object(_WorldStepRuntime, "apply_creature_damage", record_damage),
    ):
        hits = state.projectiles.step(
            PrimaryStepCtx(
                dt=case["dt"],
                creatures=world.creatures.entries,
                options=ProjectileUpdateOptions(
                    world_size=1024.0,
                    damage_scale_by_type={item["type"]: case.get("damage_scale", 2)},
                    rng=rng,
                    runtime_state=state,
                    players=world.players,
                    hit_runtime=runtime,
                    creature_damage_runtime=runtime,
                ),
            ),
        )
    assert len(hits) == 1 and not runtime.deaths
    return {
        "primary": {
            "active": int(projectile.active),
            "angle": projectile.angle,
            "x": projectile.pos.x,
            "y": projectile.pos.y,
            "origin_x": projectile.origin.x,
            "origin_y": projectile.origin.y,
            "vx": projectile.vel.x,
            "vy": projectile.vel.y,
            "type": int(projectile.type_id),
            "life": projectile.life_timer,
            "speed": projectile.speed_scale,
            "damage": projectile.damage_pool,
            "radius": projectile.hit_radius,
            "travel": projectile.travel_budget,
            "owner": projectile.owner.to_legacy(),
        },
        "creature": {
            "active": int(creature.active),
            "lifecycle": creature.lifecycle_stage,
            "x": creature.pos.x,
            "y": creature.pos.y,
            "health": creature.hp,
            "max_health": creature.max_hp,
            "size": creature.size,
            "r": creature.tint.r,
            "g": creature.tint.g,
            "b": creature.tint.b,
            "a": creature.tint.a,
            "type": int(creature.type_id),
            "vx": creature.vel.x,
            "vy": creature.vel.y,
            "heading": creature.heading,
            "hit_flash": creature.hit_flash_timer,
            "flags": int(creature.flags),
        },
        "decals": [
            [
                int(d.effect_id),
                [
                    bits(x87_pc24_sub(d.pos.x, x87_pc24_mul(d.width, 0.5))),
                    bits(x87_pc24_sub(d.pos.y, x87_pc24_mul(d.height, 0.5))),
                ],
                bits(d.width),
                bits(d.height),
                bits(d.rotation),
                [bits(c) for c in (d.color.r, d.color.g, d.color.b, d.color.a)],
            ]
            for d in runtime.fx_queue.iter_active()
        ],
        "effects": [
            [
                d.effect_id,
                [bits(d.pos.x), bits(d.pos.y)],
                [
                    bits(d.vel.x),
                    bits(d.vel.y),
                    bits(d.rotation),
                    bits(d.scale),
                    bits(d.half_width),
                    bits(d.half_height),
                    bits(d.age),
                    bits(d.lifetime),
                    d.flags,
                    bits(d.color.r),
                    bits(d.color.g),
                    bits(d.color.b),
                    bits(d.color.a),
                    bits(d.rotation_step),
                    bits(d.scale_step),
                ],
            ]
            for d in state.effects.iter_active()
        ],
        "damage_calls": damage_calls,
        "shots_hit": state.shots_hit[0],
        "splatters": splatters,
        "random_positions": random_positions,
        "rng_state": rng.state,
        "draws": [r.value for r in rng.records],
        "rng_callers": [r.caller for r in rng.records],
        "audio": [
            {
                "sfx_id": request.sfx_id.value,
                "position": [bits(request.position.x), bits(request.position.y)] if request.position is not None else None,
                "gain": bits(request.gain),
            }
            for request in runtime.hit_sfx
        ],
    }


def differences(witness, actual):
    result = []
    expected = witness["expected"]
    for category in ("primary", "creature"):
        for name, value in actual[category].items():
            if bits(value) != bits(expected[category][name]):
                result.append({"field": category + "." + name, "native": expected[category][name], "python": value})
    for key in (
        "decals",
        "random_positions",
        "splatters",
        "effects",
        "damage_calls",
        "shots_hit",
        "rng_state",
        "draws",
        "rng_callers",
    ):
        if actual[key] != expected[key]:
            result.append({"field": key, "native": expected[key], "python": actual[key]})
    if "audio" in expected and actual["audio"] != expected["audio"]:
        result.append({"field": "audio", "native": expected["audio"], "python": actual["audio"]})
    return result


def compare(witness):
    assert witness["input"]["fpcw"] == 0x7F
    assert witness["input"]["template_scale"] == 1
    failed = differences(witness, observe(witness["input"]))
    assert not failed, (witness["index"], failed)
