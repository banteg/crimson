from __future__ import annotations

import pytest

from crimson.math_parity import f32, x87_pc24_mul, x87_pc24_sub
from crimson.perks import PerkId
from crimson.player_damage import player_take_damage
from crimson.rng_caller_static import RngCallerStatic
from grim.rand import Crand
from grim.sfx_map import SfxId
from tests.support.audio import sfx_ids
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime
from tests.support.helpers import ScriptedCrand


@pytest.mark.parametrize(
    ("perks", "rand_val", "expected_applied", "expected_health"),
    [
        ({PerkId.NINJA: 1}, 6, 0.0, 100.0),
        ({PerkId.NINJA: 1}, 1, 10.0, 90.0),
        ({PerkId.DODGER: 1}, 10, 0.0, 100.0),
        ({PerkId.NINJA: 1, PerkId.DODGER: 1}, 5, 10.0, 90.0),
    ],
    ids=[
        "ninja-dodges-1-in-3",
        "ninja-applies-damage-otherwise",
        "dodger-dodges-1-in-5",
        "ninja-has-priority-over-dodger",
    ],
)
def test_player_take_damage_dodge_perks(
    perks: dict[PerkId, int],
    rand_val: int,
    expected_applied: float,
    expected_health: float,
) -> None:
    world = make_world()
    state = world.state
    state.rng = ScriptedCrand(rand_val, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    player = world.players[0]
    player.health = 100.0
    for perk_id, count in perks.items():
        state.perks[int(perk_id)] = count

    applied = player_take_damage(make_step_runtime(world), player, 10.0, dt=0.1)

    assert applied == expected_applied
    assert player.health == expected_health


def test_player_take_damage_exact_zero_kill_uses_death_path_by_default() -> None:
    rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    world = make_world(preserve_bugs=False)
    state = world.state
    state.rng = rng
    player = world.players[0]
    player.health = 100.0
    player.death_timer = 16.0
    state.perks[int(PerkId.HIGHLANDER)] = 1

    applied = player_take_damage(make_step_runtime(world), player, 10.0, dt=0.1)

    assert applied == 100.0
    assert player.health == 0.0
    assert player.death_timer == x87_pc24_sub(16.0, x87_pc24_mul(f32(0.1), 28.0))
    assert sfx_ids(state.sfx_queue) == [SfxId.TROOPER_DIE_01]
    assert [record.caller for record in rng.records_since()] == [
        RngCallerStatic.PLAYER_TAKE_DAMAGE_HIGHLANDER,
        RngCallerStatic.PLAYER_TAKE_DAMAGE_DEATH_SFX,
        RngCallerStatic.PLAYER_TAKE_DAMAGE_HEADING,
        RngCallerStatic.PLAYER_TAKE_DAMAGE_BLEED_DRIP,
    ]


def test_player_take_damage_uses_target_player_alive_guard_by_default() -> None:
    world = make_world(player_count=2, preserve_bugs=False)
    state = world.state
    state.rng = ScriptedCrand(0, fallback=ScriptedCrand.Fallback.REPEAT_LAST)
    player1, player2 = world.players
    player1.health = -1.0
    player2.health = 5.0
    player2.death_timer = 16.0

    applied = player_take_damage(make_step_runtime(world), player2, 10.0, dt=0.1)

    assert applied == 10.0
    assert player2.health == -5.0
    assert player2.death_timer == x87_pc24_sub(16.0, x87_pc24_mul(f32(0.1), 28.0))
    assert sfx_ids(state.sfx_queue) == [SfxId.TROOPER_DIE_01]


def test_player_take_damage_preserve_bugs_uses_player1_alive_guard() -> None:
    world = make_world(player_count=2, preserve_bugs=True)
    state = world.state
    state.rng = Crand(0x1234)
    player1, player2 = world.players
    player1.health = -1.0
    player2.health = 5.0
    player2.death_timer = 16.0

    applied = player_take_damage(make_step_runtime(world), player2, 10.0, dt=0.1)

    assert applied == 10.0
    assert player2.health == -5.0
    assert player2.death_timer == x87_pc24_sub(16.0, x87_pc24_mul(f32(0.1), 28.0))
    assert sfx_ids(state.sfx_queue) == []
