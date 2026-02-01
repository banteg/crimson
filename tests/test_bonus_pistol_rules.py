from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.gameplay import BonusPool, GameplayState, PlayerState
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


def test_pistol_safety_net_forces_weapon_drop() -> None:
    state = GameplayState()
    state.rng = _SequenceRng([0, 0, 0, 1])
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos_x=256.0, pos_y=256.0)

    entry = state.bonus_pool.try_spawn_on_kill(256.0, 256.0, state=state, players=[player])
    assert entry is not None
    assert entry.bonus_id == int(BonusId.WEAPON)
    assert entry.amount == int(WeaponId.ASSAULT_RIFLE)


def test_pistol_extra_gate_allows_spawn_without_bonus_magnet() -> None:
    state = GameplayState()
    state.rng = _SequenceRng([3, 0, 1, 0, 0])
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)

    entry = state.bonus_pool.try_spawn_on_kill(100.0, 100.0, state=state, players=[player])
    assert entry is not None


def test_weapon_drop_suppression_is_player1_only_in_coop() -> None:
    state = GameplayState()
    state.rng = _SequenceRng([1, 13, 1, 4])
    state.bonus_pool = BonusPool()

    player1 = PlayerState(index=0, pos_x=0.0, pos_y=0.0, weapon_id=int(WeaponId.ASSAULT_RIFLE))
    player2 = PlayerState(index=1, pos_x=500.0, pos_y=500.0, weapon_id=int(WeaponId.SUBMACHINE_GUN))

    entry = state.bonus_pool.try_spawn_on_kill(500.0, 500.0, state=state, players=[player1, player2])
    assert entry is not None
    assert entry.bonus_id == int(BonusId.WEAPON)
    assert entry.amount == int(WeaponId.SUBMACHINE_GUN)

