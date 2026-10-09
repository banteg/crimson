from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusPool
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapon_runtime.availability import prepare_weapon_availability
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.helpers import ScriptedCrand


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
