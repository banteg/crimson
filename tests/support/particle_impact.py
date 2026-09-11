"""Replay a particle collision through the real Python damage and decal helpers."""

import struct

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.effects import FxQueue, ParticlePool, ParticleStyleId, SpriteEffectPool
from crimson.math_parity import f32, x87_pc24_mul, x87_pc24_sub
from crimson.owner_ref import OwnerRef
from crimson.sim.state_types import PlayerState
from grim.color import RGBA
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.factories import RecordingCreatureDamageRuntime


def _check_fields(index, owner, expected, actual):
    for name, value in actual.items():
        native = expected[name]
        if name in ("active", "render", "style", "target", "type", "index", "effect"):
            assert value == native, (index, owner, name, value, native)
        else:
            assert struct.pack("<f", value) == struct.pack("<f", native), (index, owner, name, value, native)


def compare(witness):
    case = witness["input"]
    assert case["fpcw"] == 0x7F
    rng = RecordingCrand(Crand(case["rng_seed"]))
    pool = ParticlePool(rng=rng)
    sprites = SpriteEffectPool(rng=rng)
    fx = FxQueue()
    item = case["particles"][0]
    particle = pool.entries[item["index"]]
    particle.active = True
    particle.render_flag = bool(item["render"])
    particle.pos = Vec2(f32(item["x"]), f32(item["y"]))
    particle.vel = Vec2(f32(item["vx"]), f32(item["vy"]))
    particle.style_id = ParticleStyleId(item["style"])
    particle.target_id = item["target"]
    particle.scale_x = particle.scale_y = particle.scale_z = particle.age = 0.0
    for key in ("intensity", "angle", "spin"):
        setattr(particle, key, f32(item[key]))
    creatures = [CreatureState() for _ in range(384)]
    target = case["creatures"][0]
    creature = creatures[target["index"]]
    creature.active = True
    creature.pos = Vec2(f32(target["x"]), f32(target["y"]))
    creature.hp = f32(target["health"])
    creature.max_hp = f32(target["max_health"])
    creature.size = f32(target["size"])
    creature.lifecycle_stage = f32(target["lifecycle"])
    creature.tint = RGBA(*(f32(target[key]) for key in ("r", "g", "b", "a")))
    players = [PlayerState(index=0, pos=Vec2())]
    for perk in case.get("perks", []):
        players[0].perk_counts[perk] = 1

    class ImpactDamageRuntime(RecordingCreatureDamageRuntime):
        def apply_creature_damage(
            self,
            creature_index: int,
            damage: float,
            damage_type: int,
            impulse: Vec2,
            owner: OwnerRef,
        ) -> None:
            super().apply_creature_damage(creature_index, damage, damage_type, impulse, owner)
            creature_apply_damage(
                self.creatures[creature_index],
                damage_amount=damage,
                damage_type=damage_type,
                impulse=impulse,
                owner=owner,
                dt=case["dt"],
                players=players,
                rng=rng,
            )

    runtime = ImpactDamageRuntime(creatures=creatures, apply_damage=False)
    pool.update(case["dt"], creatures=creatures, creature_damage_runtime=runtime, sprite_effects=sprites, fx_queue=fx)
    _check_fields(
        witness["index"],
        "particle",
        witness["particle"],
        {
            "active": int(particle.active),
            "render": int(particle.render_flag),
            "x": particle.pos.x,
            "y": particle.pos.y,
            "vx": particle.vel.x,
            "vy": particle.vel.y,
            "sx": particle.scale_x,
            "sy": particle.scale_y,
            "sz": particle.scale_z,
            "age": particle.age,
            "intensity": particle.intensity,
            "angle": particle.angle,
            "spin": particle.spin,
            "style": int(particle.style_id),
            "target": particle.target_id,
        },
    )
    _check_fields(
        witness["index"],
        "creature",
        witness["creature"],
        {
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
        },
    )
    actual_sprites = [
        {
            "index": index,
            "active": int(sprite.active),
            "alpha": sprite.color.a,
            "rotation": sprite.rotation,
            "x": sprite.pos.x,
            "y": sprite.pos.y,
            "vx": sprite.vel.x,
            "vy": sprite.vel.y,
            "scale": sprite.scale,
        }
        for index, sprite in enumerate(sprites.entries)
        if sprite.active
    ]
    assert len(actual_sprites) == len(witness["sprites"]), witness["index"]
    for actual, native in zip(actual_sprites, witness["sprites"], strict=True):
        _check_fields(witness["index"], "sprite", native, actual)
    actual_decals = fx.iter_active()
    assert len(actual_decals) == len(witness["decals"]), witness["index"]
    for decal, native in zip(actual_decals, witness["decals"], strict=True):
        # The port stores the center; native fx_queue_add receives top-left.
        _check_fields(
            witness["index"],
            "decal",
            native,
            {
                "effect": int(decal.effect_id),
                "x": x87_pc24_sub(decal.pos.x, x87_pc24_mul(decal.width, 0.5)),
                "y": x87_pc24_sub(decal.pos.y, x87_pc24_mul(decal.height, 0.5)),
                "width": decal.width,
                "height": decal.height,
                "rotation": decal.rotation,
                "r": decal.color.r,
                "g": decal.color.g,
                "b": decal.color.b,
                "a": decal.color.a,
            },
        )
    assert len(runtime.calls) == len(witness["damage_calls"]), witness["index"]
    for actual, native in zip(runtime.calls, witness["damage_calls"], strict=True):
        target_id, damage, kind, impulse, _owner = actual
        assert target_id == native[0] and kind == native[2], witness["index"]
        assert struct.unpack("<I", struct.pack("<f", damage))[0] == native[1], witness["index"]
        assert [struct.unpack("<I", struct.pack("<f", value))[0] for value in (impulse.x, impulse.y)] == native[3]
    assert rng.state == witness["rng_state"], witness["index"]
    assert [record.value for record in rng.records] == witness["draws"], witness["index"]
    assert [record.caller for record in rng.records] == witness["rng_callers"], witness["index"]
