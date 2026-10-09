from __future__ import annotations

import pytest

from crimson.creatures.runtime import CreaturePool
from crimson.effects import FxQueue
from crimson.math_parity import f32, x87_pc24_add
from crimson.perks import PerkId
from crimson.perks.effects import perks_update_effects
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_float_close

_DT_0P2 = f32(0.2)
_HEAL_0P2_FROM_90 = x87_pc24_add(f32(90.0), _DT_0P2)


@pytest.mark.parametrize(
    ("preserve_bugs", "expected_player0_health", "expected_player1_health"),
    [
        (False, _HEAL_0P2_FROM_90, x87_pc24_add(f32(80.0), _DT_0P2)),
        (
            True,
            x87_pc24_add(_HEAL_0P2_FROM_90, _DT_0P2),
            80.0,
        ),
    ],
    ids=[
        "heals-all-alive-players-by-default",
        "preserve-bugs-keeps-player1-only-scaled-tick",
    ],
)
def test_perks_update_effects_regeneration_multiplayer_targeting(
    preserve_bugs: bool,
    expected_player0_health: float,
    expected_player1_health: float,
) -> None:
    state = GameplayState()
    state.rng = ScriptedCrand(1)
    state.preserve_bugs = preserve_bugs

    player0 = PlayerState(index=0, pos=Vec2(10.0, 20.0), health=90.0)
    player1 = PlayerState(index=1, pos=Vec2(30.0, 40.0), health=80.0)
    state.perks[int(PerkId.REGENERATION)] = 1

    perks_update_effects(state, [player0, player1], 0.2, creatures=CreaturePool().entries, fx_queue=FxQueue())

    assert_float_close(player0.health, expected_player0_health)
    assert_float_close(player1.health, expected_player1_health)
    assert [record.caller for record in state.rng.records_since()] == [
        RngCallerStatic.PERKS_UPDATE_EFFECTS_REGENERATION_GATE,
    ]
