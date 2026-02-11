from __future__ import annotations

from grim.geom import Vec2

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.creatures.runtime import CreaturePool
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.gameplay import GameplayState, PlayerState
from crimson.sim.world_state import WorldState


def test_freeze_pickup_shatters_existing_corpses() -> None:
    state = GameplayState()
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
        origin=player,
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


def test_freeze_stops_creature_movement_and_animation() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        difficulty_level=0,
    )

    player = PlayerState(index=0, pos=Vec2(512.0, 512.0))
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.hp = 10.0
    creature.max_hp = 10.0
    creature.pos = Vec2(100.0, 200.0)
    creature.move_speed = 1.0
    creature.ai_mode = 0
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
        game_mode=int(GameMode.SURVIVAL),
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
        game_mode=int(GameMode.SURVIVAL),
        perk_progression_enabled=False,
    )

    assert events.deaths == ()
    assert creature.pos.x == moved_x
    assert creature.pos.y == moved_y
    assert creature.anim_phase == moved_phase
