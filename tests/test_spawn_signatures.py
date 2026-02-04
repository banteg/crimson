from __future__ import annotations

from collections import Counter

from crimson.gameplay import BonusId, GameplayState, PlayerInput, PlayerState, bonus_apply, player_update
from crimson.perks import PerkId
from crimson.projectiles import ProjectilePool, ProjectileTypeId


def _signature(pool: ProjectilePool) -> Counter[int]:
    return Counter(entry.type_id for entry in pool.entries if entry.active)


def test_spawn_signature_phase1_perks_and_bonuses() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)

    # Fireblast.
    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0)
    bonus_apply(state, player, BonusId.FIREBLAST, origin=player)
    assert _signature(pool) == Counter({int(ProjectileTypeId.PLASMA_RIFLE): 16})

    pool.reset()

    # Fireblast should NOT convert to Fire Bullets because it sets bonus_spawn_guard.
    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0, fire_bullets_timer=1.0)
    bonus_apply(state, player, BonusId.FIREBLAST, origin=player, players=[player])
    assert _signature(pool) == Counter({int(ProjectileTypeId.PLASMA_RIFLE): 16})

    pool.reset()

    # Angry Reloader.
    player = PlayerState(
        index=0,
        pos_x=100.0,
        pos_y=100.0,
        reload_active=True,
        reload_timer=1.1,
        reload_timer_max=2.0,
        clip_size=10,
        ammo=0,
    )
    player.perk_counts[int(PerkId.ANGRY_RELOADER)] = 1
    player_update(player, PlayerInput(aim_x=101.0, aim_y=100.0), 0.2, state)
    assert _signature(pool) == Counter({int(ProjectileTypeId.PLASMA_MINIGUN): 15})

    pool.reset()

    # Man Bomb.
    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0, man_bomb_timer=3.9)
    player.perk_counts[int(PerkId.MAN_BOMB)] = 1
    player_update(player, PlayerInput(aim_x=101.0, aim_y=100.0), 0.2, state)
    assert _signature(pool) == Counter({int(ProjectileTypeId.ION_RIFLE): 4, int(ProjectileTypeId.ION_MINIGUN): 4})

    pool.reset()

    # Hot Tempered.
    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0, hot_tempered_timer=1.95)
    player.perk_counts[int(PerkId.HOT_TEMPERED)] = 1
    player_update(player, PlayerInput(aim_x=101.0, aim_y=100.0), 0.1, state)
    assert _signature(pool) == Counter({int(ProjectileTypeId.PLASMA_MINIGUN): 4, int(ProjectileTypeId.PLASMA_RIFLE): 4})
