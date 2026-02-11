from __future__ import annotations

from grim.geom import Vec2

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusPool
from crimson.gameplay import GameplayState, PlayerState
from crimson.weapons import WeaponId


class _SequenceRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(v) for v in values]
        self._idx = 0

    def rand(self) -> int:
        if self._idx >= len(self._values):
            return 0
        value = self._values[self._idx]
        self._idx += 1
        return int(value)

    @property
    def consumed(self) -> int:
        return int(self._idx)


def test_pistol_safety_net_forces_weapon_drop() -> None:
    state = GameplayState()
    state.rng = _SequenceRng([0, 0, 0, 1])
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos=Vec2(256.0, 256.0))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player])
    assert entry is not None
    assert entry.bonus_id == int(BonusId.WEAPON)
    assert entry.amount == int(WeaponId.ASSAULT_RIFLE)


def test_pistol_extra_gate_allows_spawn_without_bonus_magnet() -> None:
    state = GameplayState()
    state.rng = _SequenceRng([3, 0, 1, 0, 0])
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos=Vec2())

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(100.0, 100.0), state=state, players=[player])
    assert entry is not None


def test_weapon_drop_suppression_is_player1_only_in_coop() -> None:
    state = GameplayState()
    state.rng = _SequenceRng([1, 13, 1, 4])
    state.bonus_pool = BonusPool()

    player1 = PlayerState(index=0, pos=Vec2(), weapon_id=int(WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos=Vec2(500.0, 500.0), weapon_id=int(WeaponId.SUBMACHINE_GUN))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(500.0, 500.0), state=state, players=[player1, player2])
    assert entry is not None
    assert entry.bonus_id == int(BonusId.WEAPON)
    assert entry.amount == int(WeaponId.SUBMACHINE_GUN)


def test_pistol_safety_net_consumes_weapon_rng_when_spawn_pos_is_blocked() -> None:
    state = GameplayState()
    rng = _SequenceRng([0, 0, 2])
    state.rng = rng
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos=Vec2(), weapon_id=int(WeaponId.PISTOL))

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(16.0, 100.0), state=state, players=[player])
    assert entry is None
    assert rng.consumed == 3
    assert not any(slot.bonus_id != 0 for slot in state.bonus_pool.entries)


def test_spawn_gate_consumes_pick_rng_when_spacing_rejects_slot() -> None:
    state = GameplayState()
    rng = _SequenceRng([1, 0, 0])
    state.rng = rng
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos=Vec2(), weapon_id=int(WeaponId.ASSAULT_RIFLE))
    seeded = state.bonus_pool.spawn_at(pos=Vec2(100.0, 100.0), bonus_id=int(BonusId.POINTS), state=state)
    assert seeded is not None

    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(110.0, 100.0), state=state, players=[player])
    assert entry is None
    assert rng.consumed == 3
    active = [slot for slot in state.bonus_pool.entries if slot.bonus_id != 0]
    assert len(active) == 1
