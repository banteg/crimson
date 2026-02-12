from __future__ import annotations

from grim.geom import Vec2

import math

from crimson.sim.state_types import PlayerState
from crimson.perks import PerkId
from crimson.perks.helpers import perk_active
from crimson.render.world import monster_vision_fade_alpha


def test_monster_vision_fade_alpha_matches_death_stage_clamp() -> None:
    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.MONSTER_VISION)] = 1
    assert perk_active(player, PerkId.MONSTER_VISION)

    assert math.isclose(monster_vision_fade_alpha(16.0), 1.0, abs_tol=1e-9)
    assert math.isclose(monster_vision_fade_alpha(0.0), 1.0, abs_tol=1e-9)
    assert math.isclose(monster_vision_fade_alpha(-1.0), 0.9, abs_tol=1e-9)
    assert math.isclose(monster_vision_fade_alpha(-5.0), 0.5, abs_tol=1e-9)
    assert math.isclose(monster_vision_fade_alpha(-10.0), 0.0, abs_tol=1e-9)
    assert math.isclose(monster_vision_fade_alpha(-20.0), 0.0, abs_tol=1e-9)
