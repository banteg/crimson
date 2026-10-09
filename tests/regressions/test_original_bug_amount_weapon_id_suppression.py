from __future__ import annotations

import pytest

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusEntry, BonusPool
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapons import WeaponId
from grim.geom import Vec2
from grim.rand import Crand


def _spawn_on_kill(*, seed: int, weapon_id: WeaponId, preserve_bugs: bool) -> BonusEntry | None:
    state = GameplayState(rng=Crand(seed), preserve_bugs=preserve_bugs)
    state.bonus_pool = BonusPool()
    player = PlayerState(index=0, pos=Vec2(256.0, 256.0), weapon=WeaponSlot(weapon_id=weapon_id))
    return state.bonus_pool.try_spawn_on_kill(pos=Vec2(256.0, 256.0), state=state, players=[player])


# Native bug: after spawning a non-points bonus, clear it if `amount == weapon_id`.
# Each seed rolls a drop whose amount collides with the killer's weapon id.
@pytest.mark.parametrize(
    ("seed", "weapon_id", "bonus_id"),
    [
        # Nuke uses `amount=1`, which collides with Pistol `weapon_id=1`.
        (130, WeaponId.PISTOL, BonusId.NUKE),
    ],
)
def test_original_amount_weapon_id_suppression(seed: int, weapon_id: WeaponId, bonus_id: BonusId) -> None:
    fixed = _spawn_on_kill(seed=seed, weapon_id=weapon_id, preserve_bugs=False)
    assert fixed is not None
    assert fixed.bonus_id == bonus_id
    assert fixed.amount == int(weapon_id)

    assert _spawn_on_kill(seed=seed, weapon_id=weapon_id, preserve_bugs=True) is None
