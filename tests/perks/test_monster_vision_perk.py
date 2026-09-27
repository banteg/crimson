from __future__ import annotations

from crimson.render.world import monster_vision_fade_alpha
from tests.support.helpers import assert_float_close


def test_monster_vision_fade_alpha_matches_death_stage_clamp() -> None:
    assert_float_close(monster_vision_fade_alpha(16.0), 1.0)
    assert_float_close(monster_vision_fade_alpha(0.0), 1.0)
    assert_float_close(monster_vision_fade_alpha(-1.0), 0.9)
    assert_float_close(monster_vision_fade_alpha(-5.0), 0.5)
    assert_float_close(monster_vision_fade_alpha(-10.0), 0.0)
    assert_float_close(monster_vision_fade_alpha(-20.0), 0.0)
