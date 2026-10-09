from __future__ import annotations

from crimson.creatures.runtime import CreatureState
from crimson.effects import FxQueue
from crimson.perks import PerkId
from crimson.perks.effects import perks_update_effects
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2


def test_perks_update_effects_evil_eyes_defaults_to_alive_player_target_slot() -> None:
    state = GameplayState(preserve_bugs=False)

    player0 = PlayerState(index=0, pos=Vec2(), health=0.0)
    player1 = PlayerState(index=1, pos=Vec2())
    state.perks[int(PerkId.EVIL_EYES)] = 1
    player1.aim = Vec2(100.0, 200.0)

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(100.0, 200.0)
    creature.death_timer = 16.0
    creature.size = 50.0

    perks_update_effects(state, [player0, player1], 0.1, creatures=[creature], fx_queue=FxQueue())

    assert player0.evil_eyes_target_creature == -1
    assert player1.evil_eyes_target_creature == 0


def test_perks_update_effects_evil_eyes_preserve_bugs_keeps_player0_only_targeting() -> None:
    state = GameplayState(preserve_bugs=True)

    player0 = PlayerState(index=0, pos=Vec2(), health=0.0)
    player1 = PlayerState(index=1, pos=Vec2())
    state.perks[int(PerkId.EVIL_EYES)] = 1
    player1.aim = Vec2(100.0, 200.0)

    creature = CreatureState()
    creature.active = True
    creature.pos = Vec2(100.0, 200.0)
    creature.death_timer = 16.0
    creature.size = 50.0

    perks_update_effects(state, [player0, player1], 0.1, creatures=[creature], fx_queue=FxQueue())

    assert player0.evil_eyes_target_creature == -1


def test_perks_update_effects_evil_eyes_default_targets_each_alive_player() -> None:
    state = GameplayState(preserve_bugs=False)

    player0 = PlayerState(index=0, pos=Vec2())
    player1 = PlayerState(index=1, pos=Vec2())
    state.perks[int(PerkId.EVIL_EYES)] = 1
    player0.aim = Vec2(100.0, 200.0)
    player1.aim = Vec2(140.0, 200.0)

    creature0 = CreatureState()
    creature0.active = True
    creature0.pos = Vec2(100.0, 200.0)
    creature0.death_timer = 16.0
    creature0.size = 50.0

    creature1 = CreatureState()
    creature1.active = True
    creature1.pos = Vec2(140.0, 200.0)
    creature1.death_timer = 16.0
    creature1.size = 50.0

    perks_update_effects(state, [player0, player1], 0.1, creatures=[creature0, creature1], fx_queue=FxQueue())

    assert player0.evil_eyes_target_creature == 0
    assert player1.evil_eyes_target_creature == 1
