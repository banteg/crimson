from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.creatures.spawn import CreatureAiMode
from crimson.effects import FxQueue, FxQueueRotated
from crimson.owner_id import OWNER_LOCAL_PLAYER
from crimson.projectiles.runtime import projectile_spawn
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from grim.rand import Crand, RecordingCrand
from tests.support.builders.session import make_world
from tests.support.factories import make_creature_state as _creature
from tests.support.factories import make_step_runtime, place_creatures
from tests.support.helpers import ScriptedCrand


def test_freeze_pickup_shatters_existing_corpses() -> None:
    world = make_world()
    state = world.state
    state.rng = RecordingCrand(Crand(0x1234))
    player = world.players[0]
    corpse = place_creatures(world, [_creature(pos=Vec2(100.0, 200.0), hp=0.0)])[0]

    assert corpse.active
    assert not state.effects.iter_active()

    bonus_apply(
        state,
        player,
        BonusId.FREEZE,
        step_runtime=make_step_runtime(world),
        amount=1,
        origin=player.pos,
        creatures=world.creatures.entries,
        players=world.players,
        detail_preset=5,
    )

    assert not corpse.active
    freeze_effects = [
        entry for entry in state.effects.iter_active() if int(entry.effect_id) in (0x08, 0x09, 0x0A, 0x0E)
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
    world = make_world()
    player = world.players[0]
    corpse = place_creatures(world, [_creature(pos=Vec2(), hp=-1.0, lifecycle_stage=-100.0)])[0]
    bonus_apply(
        world.state,
        player,
        BonusId.FREEZE,
        amount=5,
        step_runtime=make_step_runtime(world),
        origin=player.pos,
        creatures=world.creatures.entries,
        players=world.players,
        detail_preset=5,
    )
    assert not corpse.active
    freeze_effects = [
        entry for entry in world.state.effects.iter_active() if int(entry.effect_id) in (0x08, 0x09, 0x0A, 0x0E)
    ]
    assert len(freeze_effects) == 16


def test_freeze_pickup_shatters_same_tick_projectile_kill() -> None:
    from crimson.projectiles.types import ProjectileTemplateId
    from crimson.sim.input import PlayerInput
    from crimson.sim.sessions import DeterministicSession

    world = make_world(preserve_bugs=True)
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world.state.rng = rng
    creature = world.creatures.entries[0]
    creature.active = True
    creature.hp = 1.0
    creature.pos = Vec2(200, 200)
    projectile_spawn(
        world.state,
        players=world.players,
        pos=creature.pos,
        angle=0.0,
        type_id=ProjectileTemplateId.PISTOL,
        owner_id=OWNER_LOCAL_PLAYER,
        owner_player_index=0,
    )
    world.state.bonus_pool.spawn_at(world.players[0].pos, BonusId.FREEZE, state=world.state)
    # `bonus_spawn_at` drew its 16-particle burst (64 draws) before the tick.
    tick_start = rng.calls
    session = DeterministicSession(
        world=world,
        perk_progression_enabled=False,
    )
    result = session.step_tick(dt=1 / 60, inputs=[PlayerInput(aim=Vec2(600, 512))])
    assert len(result.events.deaths) == 1
    assert [p.bonus_id for p in result.events.pickups] == [BonusId.FREEZE]
    callers = [r.caller for r in rng.records_since(tick_start)]
    assert callers.count(RngCallerStatic.BONUS_APPLY_FREEZE_SHARD_ANGLE) == 8
    assert callers.count(RngCallerStatic.BONUS_APPLY_FREEZE_SHATTER_ANGLE) == 1
    assert len(callers) == 212 + 1  # plus the frame-end draw
    assert not creature.active


def test_freeze_stops_creature_movement_and_animation() -> None:
    world = WorldState.build(
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
    creature.anim_phase = 3.0

    events = world.step(
        0.2,
        inputs=None,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
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
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        perk_progression_enabled=False,
    )

    assert events.deaths == ()
    assert creature.pos.x == moved_x
    assert creature.pos.y == moved_y
    assert creature.anim_phase == moved_phase
