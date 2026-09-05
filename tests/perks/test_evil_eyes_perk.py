from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.effects import FxQueue, FxQueueRotated
from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.perks.runtime.effects import perks_update_effects
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState
from crimson.sim.world_state import WorldState
from grim.geom import Vec2
from tests.support.helpers import assert_float_close


def test_evil_eyes_freezes_creature_under_aim() -> None:
    world_size = 1024.0
    world = WorldState.build(
        world_size=world_size,
        demo_mode_active=True,
        hardcore=False,
        quest_fail_retry_count=0,
    )
    player = PlayerState(index=0, pos=Vec2(300.0, 100.0))
    player.perk_counts[int(PerkId.EVIL_EYES)] = 1
    world.players.append(player)

    creature = world.creatures.entries[0]
    creature.active = True
    creature.pos = Vec2(100.0, 100.0)
    creature.hp = 100.0
    creature.max_hp = 100.0
    creature.size = 50.0
    creature.move_speed = 1.0

    # `perks_update_effects` evaluates Evil Eyes before `player_update` applies
    # current-frame input aim, so seed the previous-frame aim.
    player.aim = Vec2(float(creature.pos.x), float(creature.pos.y))

    before = (float(creature.pos.x), float(creature.pos.y))
    events = world.step(
        0.5,
        inputs=[PlayerInput(aim=Vec2(float(creature.pos.x), float(creature.pos.y)))],
        world_size=world_size,
        damage_scale_by_type={},
        detail_preset=5,
        fx_queue=FxQueue(),
        fx_queue_rotated=FxQueueRotated(),
        game_mode=GameMode.SURVIVAL,
        perk_progression_enabled=False,
    )
    assert events

    after = (float(creature.pos.x), float(creature.pos.y))
    assert_float_close(after[0], before[0])
    assert_float_close(after[1], before[1])


def test_perks_update_effects_evil_eyes_defaults_to_alive_player_target_slot() -> None:
    state = GameplayState(preserve_bugs=False)

    player0 = PlayerState(index=0, pos=Vec2(), health=0.0)
    player1 = PlayerState(index=1, pos=Vec2())
    player1.perk_counts[int(PerkId.EVIL_EYES)] = 1
    player1.aim = Vec2(100.0, 200.0)

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(100.0, 200.0)
    creature.lifecycle_stage = 16.0
    creature.size = 50.0

    perks_update_effects(state, [player0, player1], 0.1, creatures=[creature])

    assert player0.evil_eyes_target_creature == -1
    assert player1.evil_eyes_target_creature == 0


def test_perks_update_effects_evil_eyes_preserve_bugs_keeps_player0_only_targeting() -> None:
    state = GameplayState(preserve_bugs=True)

    player0 = PlayerState(index=0, pos=Vec2(), health=0.0)
    player1 = PlayerState(index=1, pos=Vec2())
    player1.perk_counts[int(PerkId.EVIL_EYES)] = 1
    player1.aim = Vec2(100.0, 200.0)

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(100.0, 200.0)
    creature.lifecycle_stage = 16.0
    creature.size = 50.0

    perks_update_effects(state, [player0, player1], 0.1, creatures=[creature])

    assert player0.evil_eyes_target_creature == -1


def test_perks_update_effects_evil_eyes_default_targets_each_alive_player() -> None:
    state = GameplayState(preserve_bugs=False)

    player0 = PlayerState(index=0, pos=Vec2())
    player1 = PlayerState(index=1, pos=Vec2())
    player0.perk_counts[int(PerkId.EVIL_EYES)] = 1
    player1.perk_counts[int(PerkId.EVIL_EYES)] = 1
    player0.aim = Vec2(100.0, 200.0)
    player1.aim = Vec2(140.0, 200.0)

    creature0 = CreatureState()
    creature0.active = True
    creature0.pos = Vec2(100.0, 200.0)
    creature0.lifecycle_stage = 16.0
    creature0.size = 50.0

    creature1 = CreatureState()
    creature1.active = True
    creature1.pos = Vec2(140.0, 200.0)
    creature1.lifecycle_stage = 16.0
    creature1.size = 50.0

    perks_update_effects(state, [player0, player1], 0.1, creatures=[creature0, creature1])

    assert player0.evil_eyes_target_creature == 0
    assert player1.evil_eyes_target_creature == 1


def test_perks_update_effects_evil_eyes_rejects_native_radius_equality() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.EVIL_EYES)] = 1
    player.aim = Vec2()

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(21.0, 0.0)
    creature.lifecycle_stage = 16.0
    creature.size = 42.0

    perks_update_effects(state, [player], 0.1, creatures=[creature])

    assert player.evil_eyes_target_creature == -1
