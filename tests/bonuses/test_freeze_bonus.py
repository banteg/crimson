from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.creatures.runtime import CreaturePool
from crimson.creatures.spawn import CreatureAiMode
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand


def test_freeze_pickup_shatters_existing_corpses() -> None:
    state = GameplayState()
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))

    pool = CreaturePool()
    corpse = pool.entries[0]
    corpse.active = True
    corpse.hp = 0.0
    corpse.pos = Vec2(100.0, 200.0)

    assert corpse.active
    assert not state.effects.iter_active()

    bonus_apply(
        state,
        player,
        BonusId.FREEZE,
        amount=1,
        origin=player.pos,
        creatures=pool.entries,
        players=[player],
        detail_preset=5,
    )

    assert not corpse.active
    freeze_effects = [
        entry
        for entry in state.effects.iter_active()
        if int(entry.effect_id) in (0x08, 0x09, 0x0A, 0x0E)
    ]
    assert len(freeze_effects) == 16
    tagged_callers = [
        record.caller
        for record in state.rng.records_since()
        if record.caller
        in {
            RngCallerStatic.BONUS_APPLY_FREEZE_SHARD_ANGLE,
            RngCallerStatic.BONUS_APPLY_FREEZE_SHATTER_ANGLE,
        }
    ]
    assert tagged_callers == [
        RngCallerStatic.BONUS_APPLY_FREEZE_SHARD_ANGLE,
    ] * 8 + [
        RngCallerStatic.BONUS_APPLY_FREEZE_SHATTER_ANGLE,
    ]


def test_freeze_shatters_active_corpses_below_despawn_threshold() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    pool = CreaturePool()
    corpse = pool.entries[0]
    corpse.active = True
    corpse.hp = -1.0
    corpse.lifecycle_stage = -100.0
    bonus_apply(state, player, BonusId.FREEZE, origin=player.pos, creatures=pool.entries, players=[player], detail_preset=5)
    assert not corpse.active
    assert len(state.effects.iter_active()) == 16


def test_freeze_pickup_shatters_same_tick_projectile_kill() -> None:
    from crimson.owner_ref import OwnerRef
    from crimson.projectiles.types import ProjectileTemplateId
    from crimson.sim.input import PlayerInput
    from crimson.sim.sessions import DeterministicSession
    from crimson.world.sim_world_state import SimWorldState

    sim = SimWorldState(preserve_bugs=True)
    world = sim.world_state
    world.state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    creature = world.creatures.entries[0]
    creature.active = True
    creature.hp = 1.0
    creature.pos = Vec2(200, 200)
    world.state.projectiles.spawn(
        pos=creature.pos, angle=0.0, type_id=ProjectileTemplateId.PISTOL, owner=OwnerRef.from_local_player(0),
    )
    world.state.bonus_pool.spawn_at(world.players[0].pos, BonusId.FREEZE, state=world.state, emit_burst=False)
    session = DeterministicSession(
        world=world, world_size=1024.0, damage_scale_by_type=sim.damage_scale_by_type,
        game_mode=GameMode.SURVIVAL, perk_progression_enabled=False,
    )
    result = session.step_tick(dt=1 / 60, inputs=[PlayerInput(aim=Vec2(600, 512))])
    assert len(result.step.events.deaths) == 1
    assert [p.bonus_id for p in result.step.events.pickups] == [BonusId.FREEZE]
    callers = [r.caller for r in world.state.rng.records_since()]
    assert callers.count(RngCallerStatic.BONUS_APPLY_FREEZE_SHARD_ANGLE) == 8
    assert callers.count(RngCallerStatic.BONUS_APPLY_FREEZE_SHATTER_ANGLE) == 1
    assert world.state.rng.calls == 212
    assert not creature.active


def test_freeze_stops_creature_movement_and_animation() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )

    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.max_hp = 10.0
    creature.pos = Vec2(100.0, 200.0)
    creature.move_speed = 1.0
    creature.ai_mode = CreatureAiMode.ORBIT_PLAYER
    creature.move_scale = 1.0
    creature.anim_phase = 3.0

    events = world.step(
        0.2,
        inputs=None,
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert events.deaths == ()
    moved_x = float(creature.pos.x)
    moved_y = float(creature.pos.y)
    moved_phase = float(creature.anim_phase)
    assert (moved_x, moved_y) != (100.0, 200.0)
    assert moved_phase != 3.0

    world.state.bonuses.freeze = 5.0
    events = world.step(
        0.2,
        inputs=None,
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert events.deaths == ()
    assert creature.pos.x == moved_x
    assert creature.pos.y == moved_y
    assert creature.anim_phase == moved_phase
