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
    tagged_callers = [record.caller for record in state.rng.records_since() if record.caller is not None]
    assert tagged_callers == [
        RngCallerStatic.BONUS_APPLY_FREEZE_SHARD_ANGLE,
    ] * 8 + [
        RngCallerStatic.BONUS_APPLY_FREEZE_SHATTER_ANGLE,
    ]


def test_freeze_pickup_can_limit_shatter_to_tick_start_corpses() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))

    pool = CreaturePool()
    old_corpse = pool.entries[0]
    old_corpse.active = True
    old_corpse.hp = -1.0
    old_corpse.pos = Vec2(100.0, 200.0)

    new_corpse = pool.entries[1]
    new_corpse.active = True
    new_corpse.hp = -1.0
    new_corpse.pos = Vec2(150.0, 240.0)

    bonus_apply(
        state,
        player,
        BonusId.FREEZE,
        amount=1,
        origin=player.pos,
        creatures=pool.entries,
        players=[player],
        detail_preset=5,
        freeze_corpse_indices={0},
    )

    assert not old_corpse.active
    assert not new_corpse.active
    freeze_effects = [
        entry
        for entry in state.effects.iter_active()
        if int(entry.effect_id) in (0x08, 0x09, 0x0A, 0x0E)
    ]
    assert len(freeze_effects) == 16


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
        auto_pick_perks=False,
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
        auto_pick_perks=False,
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )

    assert events.deaths == ()
    assert creature.pos.x == moved_x
    assert creature.pos.y == moved_y
    assert creature.anim_phase == moved_phase
