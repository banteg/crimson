from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusPool
from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.helpers import MockCrand, assert_rng_progression


def test_pistol_safety_net_forces_weapon_drop() -> None:
    state = GameplayState()
    state.rng = MockCrand([0, 0, 0, 1], fallback="zero")
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos=Vec2(256.0, 256.0))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player])
    assert entry is not None
    assert entry.bonus_id == BonusId.WEAPON
    assert entry.amount == WeaponId.ASSAULT_RIFLE


def test_pistol_extra_gate_allows_spawn_without_bonus_magnet() -> None:
    state = GameplayState()
    state.rng = MockCrand([3, 0, 1, 0, 0], fallback="zero")
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos=Vec2())

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(100.0, 100.0), state=state, players=[player])
    assert entry is not None


def test_pistol_extra_gate_uses_any_player_by_default() -> None:
    state = GameplayState()
    state.rng = MockCrand([3, 0, 1, 0], fallback="zero")
    state.bonus_pool = BonusPool()

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(300.0, 300.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(100.0, 100.0), state=state, players=[player1, player2])
    assert entry is not None


def test_pistol_extra_gate_preserve_bugs_uses_player1_only() -> None:
    state = GameplayState(preserve_bugs=True)
    state.rng = MockCrand([3, 0, 1, 0], fallback="zero")
    state.bonus_pool = BonusPool()

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(300.0, 300.0), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(100.0, 100.0), state=state, players=[player1, player2])
    assert entry is None


def test_weapon_drop_near_player2_converts_to_points_by_default() -> None:
    state = GameplayState()
    state.rng = MockCrand([1, 13, 1, 4], fallback="zero")
    state.bonus_pool = BonusPool()

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon=WeaponSlot(weapon_id=WeaponId.SUBMACHINE_GUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(500.0, 500.0), state=state, players=[player1, player2])
    assert entry is not None
    assert entry.bonus_id == BonusId.POINTS
    assert entry.amount == 100


def test_weapon_drop_near_player2_stays_player1_only_with_preserve_bugs() -> None:
    state = GameplayState(preserve_bugs=True)
    state.rng = MockCrand([1, 13, 1, 4], fallback="zero")
    state.bonus_pool = BonusPool()

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon=WeaponSlot(weapon_id=WeaponId.SUBMACHINE_GUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(500.0, 500.0), state=state, players=[player1, player2])
    assert entry is not None
    assert entry.bonus_id == BonusId.WEAPON
    assert entry.amount == WeaponId.SUBMACHINE_GUN


def test_pistol_safety_net_consumes_weapon_rng_when_spawn_pos_is_blocked() -> None:
    state = GameplayState()
    rng = MockCrand([0, 0, 2], fallback="zero")
    state.rng = rng
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.PISTOL))
    before_calls = rng.calls
    before_state = rng.state

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(16.0, 100.0), state=state, players=[player])
    assert entry is None
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=3,
        expected_after_state=2,
    )
    assert not any(slot.bonus_id != BonusId.UNUSED for slot in state.bonus_pool.entries)


def test_spawn_gate_consumes_pick_rng_when_spacing_rejects_slot() -> None:
    state = GameplayState()
    rng = MockCrand([1, 0, 0], fallback="zero")
    state.rng = rng
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    seeded = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=BonusId.POINTS, state=state)
    assert seeded is not None
    before_calls = rng.calls
    before_state = rng.state

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(110.0, 100.0), state=state, players=[player])
    assert entry is None
    assert_rng_progression(
        rng,
        before_calls=before_calls,
        before_state=before_state,
        expected_draws=3,
        expected_after_state=0,
    )
    active = [slot for slot in state.bonus_pool.entries if slot.bonus_id != BonusId.UNUSED]
    assert len(active) == 1


def test_weapon_drop_suppression_checks_all_carried_weapons_by_default() -> None:
    state = GameplayState()
    state.rng = MockCrand([1, 13, 1, 2], fallback="zero")
    state.bonus_pool = BonusPool()

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon=WeaponSlot(weapon_id=WeaponId.SHOTGUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player1, player2])
    assert entry is None


def test_weapon_drop_suppression_preserve_bugs_checks_player1_weapon_only() -> None:
    state = GameplayState(preserve_bugs=True)
    state.rng = MockCrand([1, 13, 1, 2], fallback="zero")
    state.bonus_pool = BonusPool()

    player1 = PlayerState(index=0, pos=Vec2(), weapon=WeaponSlot(weapon_id=WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon=WeaponSlot(weapon_id=WeaponId.SHOTGUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player1, player2])
    assert entry is not None
    assert entry.bonus_id == BonusId.WEAPON
    assert entry.amount == WeaponId.SHOTGUN
