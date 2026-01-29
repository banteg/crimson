from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.creatures.runtime import CreaturePool
from crimson.gameplay import GameplayState, PlayerState, bonus_apply


def test_nuke_damage_is_limited_to_radius() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=512.0, pos_y=512.0)

    pool = CreaturePool()
    near = pool.entries[0]
    near.active = True
    near.x = player.pos_x + 100.0
    near.y = player.pos_y
    near.hp = 10.0
    near.max_hp = 10.0

    far = pool.entries[1]
    far.active = True
    far.x = player.pos_x + 300.0
    far.y = player.pos_y
    far.hp = 10.0
    far.max_hp = 10.0

    bonus_apply(
        state,
        player,
        BonusId.NUKE,
        origin=player,
        creatures=pool.entries,
        players=[player],
        detail_preset=5,
    )

    assert near.hp <= 0.0
    assert far.hp == 10.0
