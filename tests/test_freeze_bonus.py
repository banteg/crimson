from __future__ import annotations

from crimson.bonuses import BonusId
from crimson.creatures.runtime import CreaturePool
from crimson.gameplay import GameplayState, PlayerState, bonus_apply


def test_freeze_pickup_shatters_existing_corpses() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=512.0, pos_y=512.0)

    pool = CreaturePool()
    corpse = pool.entries[0]
    corpse.active = True
    corpse.hp = 0.0
    corpse.x = 100.0
    corpse.y = 200.0

    assert corpse.active
    assert not state.effects.iter_active()

    bonus_apply(
        state,
        player,
        BonusId.FREEZE,
        amount=1,
        origin=player,
        creatures=pool.entries,
        players=[player],
        detail_preset=5,
    )

    assert not corpse.active
    freeze_effects = [
        entry
        for entry in state.effects.iter_active()
        if int(entry.effect_id) in (0x08, 0x09, 0x0A, 0x0E)
    ]
    assert len(freeze_effects) == 16
