from __future__ import annotations

from crimson.creatures.damage import creature_apply_damage
from crimson.creatures.runtime import CreatureState
from crimson.creatures.spawn import CreatureFlags
from crimson.perks import PerkId
from crimson.sim.state_types import PlayerState
from grim.geom import Vec2
from tests.helpers import MockCrand, assert_float_close, assert_rng_progression


def test_damage_type1_heading_jitter_uses_rand_without_player_attacker() -> None:
    creature = CreatureState(active=True, hp=100.0, size=50.0, flags=CreatureFlags(0), heading=0.0)
    player = PlayerState(index=0, pos=Vec2())
    rng = MockCrand(0, fallback="repeat_last")
    before_calls = rng.calls
    before_state = rng.state

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse=Vec2(),
        owner_id=38,
        dt=0.016,
        players=[player],
        rand=rng,
    )

    assert killed is False
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=1,
        expected_after_state=0,
        expected_hash="b6589fc6ab0dc82c",
    )
    assert_float_close(creature.heading, -0.1024)


def test_damage_type1_heading_jitter_skips_ping_pong_creatures() -> None:
    creature = CreatureState(
        active=True,
        hp=100.0,
        size=50.0,
        flags=CreatureFlags.ANIM_PING_PONG,
        heading=0.0,
    )
    player = PlayerState(index=0, pos=Vec2())
    rng = MockCrand(0, fallback="repeat_last")
    before_calls = rng.calls
    before_state = rng.state

    killed = creature_apply_damage(
        creature,
        damage_amount=10.0,
        damage_type=1,
        impulse=Vec2(),
        owner_id=38,
        dt=0.016,
        players=[player],
        rand=rng,
    )

    assert killed is False
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=0,
        expected_after_state=0,
        expected_hash="da39a3ee5e6b4b0d",
    )
    assert_float_close(creature.heading, 0.0)


def test_damage_type1_global_perks_apply_with_non_player_owner() -> None:
    creature = CreatureState(active=True, hp=74.0413, size=50.0, flags=CreatureFlags(0), heading=0.0)
    player = PlayerState(index=0, pos=Vec2())
    player.perk_counts[int(PerkId.URANIUM_FILLED_BULLETS)] = 1
    player.perk_counts[int(PerkId.BARREL_GREASER)] = 1

    killed = creature_apply_damage(
        creature,
        damage_amount=73.5593,
        damage_type=1,
        impulse=Vec2(),
        owner_id=10,
        dt=0.016,
        players=[player],
        rand=lambda: 0,
    )

    assert killed is True
    assert_float_close(creature.hp, -131.92474)
