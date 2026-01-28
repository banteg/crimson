from __future__ import annotations

from dataclasses import dataclass
import math

from grim.rand import Crand
from crimson.gameplay import (
    BonusId,
    GameplayState,
    PlayerInput,
    PlayerState,
    bonus_apply,
    bonus_hud_update,
    player_fire_weapon,
    player_update,
)
from crimson.perks import PerkId
from crimson.projectiles import ProjectilePool


@dataclass(slots=True)
class _Creature:
    x: float
    y: float
    hp: float
    size: float = 50.0


def _active_type_ids(pool: ProjectilePool) -> list[int]:
    return [entry.type_id for entry in pool.entries if entry.active]


def test_player_update_weapon_power_up_scales_shot_cooldown_decay() -> None:
    state = GameplayState()
    state.bonuses.weapon_power_up = 1.0

    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0, shot_cooldown=1.0)
    player_update(player, PlayerInput(aim_x=101.0, aim_y=100.0), 0.5, state)

    assert math.isclose(player.shot_cooldown, 0.25, abs_tol=1e-9)


def test_player_update_stationary_reloader_tripples_reload_decay() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos_x=50.0,
        pos_y=50.0,
        reload_active=True,
        reload_timer=1.0,
        reload_timer_max=1.0,
        clip_size=10,
        ammo=0,
    )
    player.perk_counts[int(PerkId.STATIONARY_RELOADER)] = 1

    player_update(player, PlayerInput(aim_x=51.0, aim_y=50.0), 0.1, state)

    assert math.isclose(player.reload_timer, 0.7, abs_tol=1e-9)


def test_player_update_angry_reloader_spawns_ring_at_half() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
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

    type_ids = _active_type_ids(pool)
    assert type_ids.count(0x0A) == 15


def test_player_update_man_bomb_spawns_8_projectiles_when_charged() -> None:
    pool = ProjectilePool(size=32)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0, man_bomb_timer=3.9)
    player.perk_counts[int(PerkId.MAN_BOMB)] = 1

    player_update(player, PlayerInput(aim_x=101.0, aim_y=100.0), 0.2, state)

    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 8
    assert type_ids.count(0x14) == 4
    assert type_ids.count(0x15) == 4


def test_player_update_fire_cough_spawns_fire_bullet_projectile() -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0, fire_cough_timer=1.95)
    player.perk_counts[int(PerkId.FIRE_CAUGH)] = 1

    player_update(player, PlayerInput(aim_x=101.0, aim_y=100.0), 0.1, state)

    type_ids = _active_type_ids(pool)
    assert type_ids == [0x2C]


def test_player_fire_weapon_fire_bullets_spawns_weapon_pellet_count() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0, weapon_id=2, clip_size=10, ammo=10, fire_bullets_timer=1.0)
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0

    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=101.0, aim_y=100.0), 0.0, state)

    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 12
    assert set(type_ids) == {0x2C}


def test_player_fire_weapon_shotgun_spawns_pellets() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0, weapon_id=2, clip_size=10, ammo=10)
    player.aim_dir_x = 1.0
    player.aim_dir_y = 0.0

    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=101.0, aim_y=100.0), 0.0, state)

    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 12
    assert set(type_ids) == {2}


def test_player_update_tracks_aim_point() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=10.0, pos_y=20.0)
    input_state = PlayerInput(aim_x=123.0, aim_y=456.0)

    player_update(player, input_state, 0.1, state)

    assert player.aim_x == 123.0
    assert player.aim_y == 456.0


def test_player_fire_weapon_uses_disc_spread_jitter() -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(projectiles=pool)

    seed = 0xBEEF
    state.rng.srand(seed)

    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0, weapon_id=1, clip_size=10, ammo=10, spread_heat=0.2)

    aim_x = 200.0
    aim_y = 100.0

    expected_rng = Crand(seed)
    rand_dir = expected_rng.rand()
    rand_mag = expected_rng.rand()

    dx = aim_x - player.pos_x
    dy = aim_y - player.pos_y
    dist = math.hypot(dx, dy)
    max_offset = dist * player.spread_heat * 0.5
    dir_angle = float(rand_dir & 0x1FF) * (math.tau / 512.0)
    mag = float(rand_mag & 0x1FF) * (1.0 / 512.0)
    offset = max_offset * mag
    jitter_x = aim_x + math.cos(dir_angle) * offset
    jitter_y = aim_y + math.sin(dir_angle) * offset
    expected_angle = math.atan2(jitter_y - player.pos_y, jitter_x - player.pos_x) + math.pi / 2.0

    player_fire_weapon(player, PlayerInput(fire_down=True, aim_x=aim_x, aim_y=aim_y), 0.0, state)

    projectiles = pool.iter_active()
    assert len(projectiles) == 1
    assert math.isclose(projectiles[0].angle, expected_angle, abs_tol=1e-9)


def test_player_update_hot_tempered_spawns_ring() -> None:
    pool = ProjectilePool(size=16)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0, hot_tempered_timer=1.95)
    player.perk_counts[int(PerkId.HOT_TEMPERED)] = 1

    player_update(player, PlayerInput(aim_x=101.0, aim_y=100.0), 0.1, state)

    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 8
    assert type_ids.count(8) == 4
    assert type_ids.count(0x0A) == 4


def test_bonus_apply_registers_hud_slot_and_expires() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos_x=100.0, pos_y=100.0)

    bonus_apply(state, player, BonusId.WEAPON_POWER_UP, amount=3)
    bonus_hud_update(state, [player])

    assert any(slot.active and slot.bonus_id == int(BonusId.WEAPON_POWER_UP) for slot in state.bonus_hud.slots)

    state.bonuses.weapon_power_up = 0.0
    bonus_hud_update(state, [player])
    assert not any(slot.active and slot.bonus_id == int(BonusId.WEAPON_POWER_UP) for slot in state.bonus_hud.slots)


def test_bonus_apply_shock_chain_spawns_projectile_and_chains() -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos_x=0.0, pos_y=0.0)
    creatures = [
        _Creature(x=50.0, y=0.0, hp=100.0),
        _Creature(x=80.0, y=0.0, hp=100.0),
    ]

    bonus_apply(state, player, BonusId.SHOCK_CHAIN, origin=player, creatures=creatures)
    assert state.shock_chain_links_left == 0x20
    first_proj = state.shock_chain_projectile_id
    assert first_proj >= 0

    pool.update(0.1, creatures, world_size=1024.0, rng=lambda: 0, runtime_state=state)

    assert state.shock_chain_links_left == 0x20
    assert state.shock_chain_projectile_id == first_proj
    assert sum(1 for entry in pool.entries if entry.active) == 1

    pool.update(0.1, creatures, world_size=1024.0, rng=lambda: 0, runtime_state=state)

    assert state.shock_chain_links_left < 0x20
    assert state.shock_chain_projectile_id != first_proj
    assert sum(1 for entry in pool.entries if entry.active) >= 2
