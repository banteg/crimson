from __future__ import annotations

from grim.geom import Vec2

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusPool
from crimson.gameplay import GameplayState
from crimson.sim.state_types import PlayerState
from crimson.weapons import WeaponId


class _SeqRng:
    def __init__(self, values: list[int]) -> None:
        self._values = [int(v) for v in values] or [0]
        self._idx = 0

    def rand(self) -> int:
        if self._idx >= len(self._values):
            return int(self._values[-1])
        value = int(self._values[self._idx])
        self._idx += 1
        return value


def test_original_amount_weapon_id_suppression_bug_is_fixed_by_default() -> None:
    # Native bug: after spawning a non-points bonus, clear it if `amount == weapon_id`.
    # Example collision: Speed uses `amount=8`, which collides with Flamethrower `weapon_id=8`.
    state = GameplayState(rng=_SeqRng([1, 114]))
    state.preserve_bugs = False
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos=Vec2(256.0, 256.0), weapon_id=int(WeaponId.FLAMETHROWER))
    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player])
    assert entry is not None
    assert entry.bonus_id == int(BonusId.SPEED)


def test_original_amount_weapon_id_suppression_bug_can_be_preserved() -> None:
    state = GameplayState(rng=_SeqRng([1, 114]))
    state.preserve_bugs = True
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos=Vec2(256.0, 256.0), weapon_id=int(WeaponId.FLAMETHROWER))
    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player])
    assert entry is None


def test_original_amount_weapon_id_suppression_handles_nuke_amount_domain() -> None:
    # Force the non-pistol-special drop path and a Nuke roll:
    # - rand#1: pistol special-case gate -> skip ((v & 3) >= 3)
    # - rand#2: base_roll where base_roll % 9 != 1
    # - rand#3: allow_without_magnet when pistol -> True (v % 5 == 1)
    # - rand#4: bonus_pick_random_type roll -> 35 => Nuke
    state = GameplayState(rng=_SeqRng([3, 0, 1, 34]))
    state.preserve_bugs = True
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos=Vec2(256.0, 256.0), weapon_id=int(WeaponId.PISTOL))
    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player])
    assert entry is None


def test_original_amount_weapon_id_suppression_handles_double_xp_amount_domain() -> None:
    # Force the non-pistol-special path and a Double Experience roll:
    # - rand#1: pistol special-case gate -> skip ((v & 3) >= 3)
    # - rand#2: base_roll where base_roll % 9 == 1
    # - rand#3: bonus_pick_random_type roll -> 45 => Double Experience
    state = GameplayState(rng=_SeqRng([3, 1, 44]))
    state.preserve_bugs = True
    state.bonus_pool = BonusPool()

    player = PlayerState(index=0, pos=Vec2(256.0, 256.0), weapon_id=int(WeaponId.PISTOL))
    entry = state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player])
    assert entry is None
