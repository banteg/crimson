from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusPool
from crimson.cl_build import ClBuild
from crimson.perks import PerkId
from crimson.rng_caller_static import RngCallerStatic
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime.availability import prepare_weapon_availability
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand, assert_rng_progression


def _init_bonus_state(state: GameplayState) -> GameplayState:
    state.bonus_pool = BonusPool()
    prepare_weapon_availability(state)
    return state


def test_pistol_safety_net_preserve_bugs_requires_exact_two_player_slice() -> None:
    state = _init_bonus_state(GameplayState(preserve_bugs=True))
    rng = ScriptedCrand([0], fallback=ScriptedCrand.Fallback.RAISE)
    state.rng = rng

    players = [
        PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)),
        PlayerState(index=1, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL)),
        PlayerState(index=2, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)),
    ]

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=players)

    assert entry is None
    assert rng.calls == 1


def test_pistol_safety_net_preserve_bugs_admits_player_two_in_two_player_slice() -> None:
    state = _init_bonus_state(GameplayState(preserve_bugs=True))
    state.rng = ScriptedCrand([0, 0, 0, 1], fallback=ScriptedCrand.Fallback.ZERO)

    players = [
        PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE)),
        PlayerState(index=1, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL)),
    ]

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=players)

    assert entry is not None
    assert entry.bonus_id == BonusId.WEAPON


def test_pistol_extra_gate_uses_any_player_by_default() -> None:
    state = _init_bonus_state(GameplayState())
    state.rng = ScriptedCrand([3, 0, 1, 0], fallback=ScriptedCrand.Fallback.ZERO)

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(300.0, 300.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(100.0, 100.0), state=state, players=[player1, player2])
    assert entry is not None


def test_pistol_extra_gate_preserve_bugs_uses_player1_only() -> None:
    state = _init_bonus_state(GameplayState(preserve_bugs=True))
    state.rng = ScriptedCrand([3, 0, 1, 0], fallback=ScriptedCrand.Fallback.ZERO)

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(300.0, 300.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(100.0, 100.0), state=state, players=[player1, player2])
    assert entry is None


def test_weapon_drop_near_player2_converts_to_points_by_default() -> None:
    state = _init_bonus_state(GameplayState())
    state.rng = ScriptedCrand([1, 13, 1, 4], fallback=ScriptedCrand.Fallback.ZERO)

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon=WeaponSlot(weapon_id=WeaponId.SUBMACHINE_GUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(500.0, 500.0), state=state, players=[player1, player2])
    assert entry is not None
    assert entry.bonus_id == BonusId.POINTS
    assert entry.amount == 100


def test_weapon_drop_near_player2_stays_player1_only_with_preserve_bugs() -> None:
    state = _init_bonus_state(GameplayState(preserve_bugs=True))
    state.rng = ScriptedCrand([1, 13, 1, 4], fallback=ScriptedCrand.Fallback.ZERO)

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon=WeaponSlot(weapon_id=WeaponId.SUBMACHINE_GUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(500.0, 500.0), state=state, players=[player1, player2])
    assert entry is not None
    assert entry.bonus_id == BonusId.WEAPON
    assert entry.amount == WeaponId.SUBMACHINE_GUN


def test_weapon_drop_suppression_checks_all_carried_weapons_by_default() -> None:
    state = _init_bonus_state(GameplayState())
    state.rng = ScriptedCrand([1, 13, 1, 2], fallback=ScriptedCrand.Fallback.ZERO)

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon=WeaponSlot(weapon_id=WeaponId.SHOTGUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player1, player2])
    assert entry is None


def test_weapon_drop_suppression_preserve_bugs_checks_player1_weapon_only() -> None:
    state = _init_bonus_state(GameplayState(preserve_bugs=True))
    state.rng = ScriptedCrand([1, 13, 1, 2], fallback=ScriptedCrand.Fallback.ZERO)

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon=WeaponSlot(weapon_id=WeaponId.SHOTGUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player1, player2])
    assert entry is not None
    assert entry.bonus_id == BonusId.WEAPON
    assert entry.amount == WeaponId.SHOTGUN


@pytest.mark.parametrize("preserve_bugs", [False, True])
@pytest.mark.parametrize("cl_build", list(ClBuild))
def test_my_favourite_weapon_rejects_the_pistol_forced_drop_except_with_1_9_8_bugs(cl_build, preserve_bugs) -> None:
    state = _init_bonus_state(GameplayState(cl_build=cl_build, preserve_bugs=preserve_bugs))
    state.perks[PerkId.MY_FAVOURITE_WEAPON] = 1
    # Force gate, the spawn's type roll and Points amount, then the drop's weapon pick (Assault Rifle).
    rng = ScriptedCrand([0, 0, 0, 1], fallback=ScriptedCrand.Fallback.ZERO)
    state.rng = rng
    player = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player])

    # 1.9.8 has no My Favourite Weapon rejection (original bug 60): the drop stays and spawns
    # its 16-particle burst, four draws a particle.
    if cl_build == ClBuild.V1_9_8 and preserve_bugs:
        assert entry is not None
        assert (entry.bonus_id, entry.amount) == (BonusId.WEAPON, WeaponId.ASSAULT_RIFLE)
        assert_rng_progression(rng, before_calls=0, before_state=0, expected_draws=4 + 16 * 4)
        assert {record.caller for record in rng.records_since(4)} == {
            RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BURST_ROTATION,
            RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BURST_VEL_X,
            RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BURST_VEL_Y,
            RngCallerStatic.BONUS_TRY_SPAWN_ON_KILL_BURST_SCALE_STEP,
        }
    else:
        assert entry is None
        assert_rng_progression(rng, before_calls=0, before_state=0, expected_draws=4)
    assert sum(bonus.bonus_id != BonusId.UNUSED for bonus in state.bonus_pool.entries) == (entry is not None)
