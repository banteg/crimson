from __future__ import annotations

import pytest

from crimson.render.rtx.heat_vision import FROZEN_WARMTH, heat_visibility, heat_warmth
from grim.color import RGBA
from tests.render.test_material_lights import frame


def test_hidden_evil_aliens_show_in_full_and_corpses_cool() -> None:
    snapshot = frame()
    alien = snapshot.creatures.entries[0]
    # Hidden Evil's faintest alien: Monster Vision is the only way to see it.
    alien.active, alien.death_timer, alien.tint = True, 16.0, RGBA(.1, .7, .51, .04)
    assert heat_visibility(alien, entity_alpha=1.0) == heat_warmth(alien, snapshot, entity_alpha=1.0) == 1.0
    alien.death_timer = -5.0
    assert heat_warmth(alien, snapshot, entity_alpha=1.0) == .5
    assert heat_visibility(alien, entity_alpha=.5) == .25


def test_freeze_cools_monsters_without_hiding_them() -> None:
    snapshot = frame()
    spider = snapshot.creatures.entries[0]
    spider.active, spider.death_timer = True, 16.0
    snapshot.state.bonuses.freeze = 4.0
    assert heat_visibility(spider, entity_alpha=1.0) == 1.0
    assert heat_warmth(spider, snapshot, entity_alpha=1.0) == pytest.approx(FROZEN_WARMTH)
    snapshot.state.bonuses.freeze = .5  # thawing with the ice's own fade
    assert FROZEN_WARMTH < heat_warmth(spider, snapshot, entity_alpha=1.0) < 1.0

