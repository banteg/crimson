"""Observe real primary movement and world-adapter player damage."""

import struct
from unittest.mock import patch

from crimson.effects import FxQueue
from crimson.game_modes import GameMode
from crimson.owner_ref import OwnerRef
from crimson.projectiles.runtime import PrimaryStepCtx, ProjectileUpdateOptions
from crimson.projectiles.runtime.spatial_hash import CreatureSpatialHash
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState, _WorldStepRuntime
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand


def observe(case):
    world = WorldState.build(world_size=1024.0, demo_mode_active=True, hardcore=False, quest_fail_retry_count=0)
    state = world.state
    rng = RecordingCrand(Crand(case["rng_seed"]))
    state.rng = rng
    state.shock_chain_projectile_id = case.get("shock_id", -1)
    item = case["primary"][0]
    projectile = state.projectiles.entries[item["index"]]
    projectile.active = True
    projectile.angle = item["angle"]
    projectile.pos = Vec2(item["x"], item["y"])
    projectile.type_id = ProjectileTemplateId(item["type"])
    projectile.life_timer = item["life"]
    projectile.speed_scale = item["speed"]
    projectile.damage_pool = 0.0
    projectile.hit_radius = item["radius"]
    projectile.travel_budget = item["travel"]
    projectile.owner = OwnerRef.from_legacy(item["owner"])
    projectile.hits_players = item["owner"] != -100
    for item in case.get("players", []):
        world.players.append(
            PlayerState(
                index=item["index"],
                pos=Vec2(item["x"], item["y"]),
                health=item["health"],
                size=item["size"],
                shield_timer=item["shield"],
            ),
        )
    runtime = _WorldStepRuntime(
        world=world,
        dt=case["dt"],
        world_size=1024.0,
        detail_preset=5,
        violence_disabled=0,
        fx_queue=FxQueue(),
        game_mode=GameMode.SURVIVAL,
        hit_audio_game_tune_started=True,
        deaths=[],
        sfx=[],
    )
    queries = []
    candidate_indices = CreatureSpatialHash.candidate_indices

    def record_query(self, *, pos, radius):
        queries.append([pos.x, pos.y])
        return candidate_indices(self, pos=pos, radius=radius)

    with patch.object(CreatureSpatialHash, "candidate_indices", record_query):
        hits = state.projectiles.step(
            PrimaryStepCtx(
                dt=case["dt"],
                creatures=world.creatures.entries,
                options=ProjectileUpdateOptions(
                    world_size=1024.0,
                    damage_scale_by_type={},
                    rng=rng,
                    runtime_state=state,
                    players=world.players,
                    hit_runtime=runtime,
                    creature_damage_runtime=runtime,
                ),
            ),
        )
    assert not hits and not runtime.sfx and not runtime.hit_sfx and not runtime.deaths
    assert rng.calls == 0
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
        "players": [
            {
                "x": player.pos.x,
                "y": player.pos.y,
                "health": player.health,
                "size": player.size,
                "shield": player.shield_timer,
            }
            for player in world.players
        ],
        "creature_queries": queries,
        "rng_state": rng.state,
    }


def differences(witness, actual):
    result = []
    rows = [("primary", witness["primary"], actual["primary"])]
    rows.extend(
        (f"player[{index}]", native, player)
        for index, (native, player) in enumerate(
            zip(witness["players"], actual["players"], strict=True),
        )
    )
    for label, native, port in rows:
        for field, value in port.items():
            if field in ("active", "type", "owner"):
                same = native[field] == value
            else:
                same = struct.pack("<f", native[field]) == struct.pack("<f", value)
            if not same:
                result.append({"field": f"{label}.{field}", "native": native[field], "python": value})
    for key in ("creature_queries", "rng_state"):
        if witness[key] != actual[key]:
            result.append({"field": key, "native": witness[key], "python": actual[key]})
    return result


def compare(witness):
    assert witness["input"]["fpcw"] == 0x7F
    failed = differences(witness, observe(witness["input"]))
    assert not failed, (witness["index"], failed)
