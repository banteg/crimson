from __future__ import annotations

from collections import Counter

from crimson.bonuses import BonusId
from crimson.bonuses.apply import bonus_apply
from crimson.perks import PerkId
from crimson.projectiles.runtime import ProjectilePool
from crimson.projectiles.types import ProjectileTemplateId
from crimson.sim.state_types import PlayerState, WeaponSlot
from crimson.weapons import WeaponId
from grim.geom import Vec2
from tests.support.builders.session import make_world
from tests.support.factories import make_step_runtime, player_input, step_player


def _signature(pool: ProjectilePool) -> Counter[int]:
    return Counter(entry.type_id for entry in pool.entries if entry.active)


def test_spawn_signature_phase1_perks_and_bonuses() -> None:
    world = make_world()
    state = world.state
    pool = state.projectiles

    def _fireblast(player: PlayerState) -> None:
        bonus_apply(
            state,
            player,
            BonusId.FIREBLAST,
            amount=1,
            step_runtime=make_step_runtime(world),
            origin=player.pos,
            creatures=world.creatures.entries,
            players=world.players,
        )

    # Fireblast.
    state.scripted_burst_active = True
    player = world.players[0]
    player.pos = Vec2(100.0, 100.0)
    _fireblast(player)
    assert _signature(pool) == Counter({int(ProjectileTemplateId.PLASMA_RIFLE): 16})
    assert not state.scripted_burst_active

    pool.reset()

    # Fireblast should NOT convert to Fire Bullets because it sets scripted_burst_active.
    player.fire_bullets_timer = 1.0
    _fireblast(player)
    assert _signature(pool) == Counter({int(ProjectileTemplateId.PLASMA_RIFLE): 16})

    pool.reset()

    # Angry Reloader.
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        weapon=WeaponSlot(
            weapon_id=WeaponId.PISTOL,
            clip_size=10,
            ammo=0,
            reload_active=True,
            reload_timer=1.1,
            reload_timer_max=2.0,
        ),
    )
    state.perks[int(PerkId.ANGRY_RELOADER)] = 1
    world.players[:] = [player]
    step_player(world, player, player_input(aim=Vec2(101.0, 100.0)), 0.2)
    assert _signature(pool) == Counter({int(ProjectileTemplateId.PLASMA_MINIGUN): 15})

    pool.reset()

    # Man Bomb.
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), man_bomb_timer=3.9)
    state.perks[int(PerkId.MAN_BOMB)] = 1
    world.players[:] = [player]
    step_player(world, player, player_input(aim=Vec2(101.0, 100.0)), 0.2)
    assert _signature(pool) == Counter(
        {int(ProjectileTemplateId.ION_RIFLE): 4, int(ProjectileTemplateId.ION_MINIGUN): 4},
    )

    pool.reset()

    # Hot Tempered.
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), hot_tempered_timer=1.95)
    state.perks[int(PerkId.HOT_TEMPERED)] = 1
    world.players[:] = [player]
    step_player(world, player, player_input(aim=Vec2(101.0, 100.0)), 0.1)
    assert _signature(pool) == Counter(
        {int(ProjectileTemplateId.PLASMA_MINIGUN): 4, int(ProjectileTemplateId.PLASMA_RIFLE): 4},
    )
