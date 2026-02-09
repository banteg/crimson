from __future__ import annotations

from grim.geom import Vec2

import pytest

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureFlags
from crimson.gameplay import PlayerState


def test_damage_type1_heading_jitter_uses_rand_without_player_attacker() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0, flags=CreatureFlags(0), heading=0.0)
    player = PlayerState(index=0, pos=Vec2())
    rand_calls = 0

    def _rand() -> int:
        nonlocal rand_calls
        rand_calls += 1
        return 0

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse=Vec2(),
        owner_id=38,
        dt=0.016,
        players=[player],
        rand=_rand,
    )

    assert killed is False
    assert rand_calls == 1
    assert creature.heading == pytest.approx(-0.1024, abs=1e-6)


def test_damage_type1_heading_jitter_skips_ping_pong_creatures() -> None:
    creature = CreatureState(
        active=True,
        hp=100.0,
        size=50.0,
        flags=CreatureFlags.ANIM_PING_PONG,
        heading=0.0,
    )
    player = PlayerState(index=0, pos=Vec2())
    rand_calls = 0

    def _rand() -> int:
        nonlocal rand_calls
        rand_calls += 1
        return 0

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse=Vec2(),
        owner_id=38,
        dt=0.016,
        players=[player],
        rand=_rand,
    )

    assert killed is False
    assert rand_calls == 0
    assert creature.heading == pytest.approx(0.0)
