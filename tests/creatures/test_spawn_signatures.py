from __future__ import annotations

from collections import Counter

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.gameplay import player_update
from crimson.perks import PerkId
from crimson.projectiles.runtime import ProjectilePool
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.gameplay_state import GameplayState
from crimson.sim.input import PlayerInput
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapons import WeaponId
from grim.geom import Vec2


def _signature(pool: ProjectilePool) -> Counter[int]:
    return Counter(entry.type_id for entry in pool.entries if entry.active)


def test_spawn_signature_phase1_perks_and_bonuses() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)

    # Fireblast.
    state.bonus_spawn_guard = True
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))
    bonus_apply(state, player, BonusId.FIREBLAST, origin=player.pos, creatures=[], players=[player])
    assert _signature(pool) == Counter({int(ProjectileTemplateId.PLASMA_RIFLE): 16})
    assert not state.bonus_spawn_guard

    pool.reset()

    # Fireblast should NOT convert to Fire Bullets because it sets bonus_spawn_guard.
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), fire_bullets_timer=1.0)
    bonus_apply(state, player, BonusId.FIREBLAST, origin=player.pos, creatures=[], players=[player])
    assert _signature(pool) == Counter({int(ProjectileTemplateId.PLASMA_RIFLE): 16})

    pool.reset()

    # Angry Reloader.
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(weapon_id=WeaponId.PISTOL, clip_size=10,
        ammo=0,
        reload_active=True,
        reload_timer=1.1,
        reload_timer_max=2.0,),
    )
    player.perk_counts[int(PerkId.ANGRY_RELOADER)] = 1
    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.2, state)
    assert _signature(pool) == Counter({int(ProjectileTemplateId.PLASMA_MINIGUN): 15})

    pool.reset()

    # Man Bomb.
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), man_bomb_timer=3.9)
    player.perk_counts[int(PerkId.MAN_BOMB)] = 1
    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.2, state)
    assert _signature(pool) == Counter({int(ProjectileTemplateId.ION_RIFLE): 4, int(ProjectileTemplateId.ION_MINIGUN): 4})

    pool.reset()

    # Hot Tempered.
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), hot_tempered_timer=1.95)
    player.perk_counts[int(PerkId.HOT_TEMPERED)] = 1
    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.1, state)
    assert _signature(pool) == Counter({int(ProjectileTemplateId.PLASMA_MINIGUN): 4, int(ProjectileTemplateId.PLASMA_RIFLE): 4})
