from __future__ import annotations

from grim.geom import Vec2

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
    weapon_assign_player,
)
from crimson.perks import PerkId
from crimson.projectiles import ProjectilePool, ProjectileTypeId
from crimson.weapons import WeaponId


@dataclass(slots=True)
class _Creature:
    pos: Vec2
    hp: float
    size: float = 50.0
    active: bool = True
    hitbox_size: float = 16.0
    flags: int = 0
    plague_infected: bool = False


def _active_type_ids(pool: ProjectilePool) -> list[int]:
    return [entry.type_id for entry in pool.entries if entry.active]


def test_player_update_weapon_power_up_scales_shot_cooldown_decay() -> None:
    state = GameplayState()
    state.bonuses.weapon_power_up = 1.0

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), shot_cooldown=1.0)
    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.5, state)

    assert math.isclose(player.shot_cooldown, 0.25, abs_tol=1e-9)


def test_player_update_stationary_reloader_tripples_reload_decay() -> None:
    state = GameplayState()
    player = PlayerState(
        index=0,
        pos=Vec2(50.0, 50.0),
        reload_active=True,
        reload_timer=1.0,
        reload_timer_max=1.0,
        clip_size=10,
        ammo=0,
    )
    player.perk_counts[int(PerkId.STATIONARY_RELOADER)] = 1

    player_update(player, PlayerInput(aim=Vec2(51.0, 50.0)), 0.1, state)

    assert math.isclose(player.reload_timer, 0.7, abs_tol=1e-9)


def test_player_update_angry_reloader_spawns_ring_at_half() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(
        index=0,
        pos=Vec2(100.0, 100.0),
        reload_active=True,
        reload_timer=1.1,
        reload_timer_max=2.0,
        clip_size=10,
        ammo=0,
    )
    player.perk_counts[int(PerkId.ANGRY_RELOADER)] = 1

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.2, state)

    owner_ids = {int(entry.owner_id) for entry in pool.entries if entry.active}
    assert owner_ids == {-100}
    type_ids = _active_type_ids(pool)
    assert type_ids.count(0x0B) == 15


def test_player_update_man_bomb_spawns_8_projectiles_when_charged() -> None:
    pool = ProjectilePool(size=32)
    state = GameplayState(projectiles=pool)
    state.bonus_spawn_guard = True
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), man_bomb_timer=3.9)
    player.perk_counts[int(PerkId.MAN_BOMB)] = 1

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.2, state)

    assert state.bonus_spawn_guard
    owner_ids = {int(entry.owner_id) for entry in pool.entries if entry.active}
    assert owner_ids == {-100}
    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 8
    assert type_ids.count(0x16) == 4
    assert type_ids.count(0x15) == 4


def test_player_update_fire_cough_spawns_fire_bullet_projectile() -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), fire_cough_timer=1.95)
    player.perk_counts[int(PerkId.FIRE_CAUGH)] = 1

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.1, state)

    owner_ids = {int(entry.owner_id) for entry in pool.entries if entry.active}
    assert owner_ids == {-100}
    type_ids = _active_type_ids(pool)
    assert type_ids == [0x2D]


def test_player_fire_weapon_fire_bullets_spawns_weapon_pellet_count() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), weapon_id=3, clip_size=10, ammo=10, fire_bullets_timer=1.0)
    player.aim_dir = Vec2(1.0, 0.0)

    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(101.0, 100.0)), 0.0, state)

    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 12
    assert set(type_ids) == {0x2D}


def test_player_fire_weapon_fire_bullets_overrides_rocket_weapons() -> None:
    from crimson.weapons import WEAPON_BY_ID

    rocket_weapon_ids = (
        WeaponId.ROCKET_LAUNCHER,
        WeaponId.SEEKER_ROCKETS,
        WeaponId.MINI_ROCKET_SWARMERS,
        WeaponId.ROCKET_MINIGUN,
    )

    for weapon_id in rocket_weapon_ids:
        pool = ProjectilePool(size=64)
        state = GameplayState(projectiles=pool)
        player = PlayerState(index=0, pos=Vec2())
        player.aim_dir = Vec2(1.0, 0.0)
        player.spread_heat = 0.0
        weapon_assign_player(player, weapon_id)

        player.fire_bullets_timer = 1.0

        player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(200.0, 0.0)), dt=0.016, state=state)

        weapon = WEAPON_BY_ID.get(int(weapon_id))
        assert weapon is not None
        assert weapon.pellet_count is not None

        type_ids = _active_type_ids(pool)
        assert len(type_ids) == int(weapon.pellet_count)
        assert set(type_ids) == {int(ProjectileTypeId.FIRE_BULLETS)}
        assert not any(entry.active for entry in state.secondary_projectiles.entries)


def test_player_fire_weapon_fire_bullets_does_not_consume_ammo() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), weapon_id=3, clip_size=10, ammo=10, fire_bullets_timer=1.0)
    player.aim_dir = Vec2(1.0, 0.0)

    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(101.0, 100.0)), 0.0, state)

    assert math.isclose(player.ammo, 10.0, abs_tol=1e-9)


def test_player_fire_weapon_fire_bullets_can_fire_at_zero_ammo_and_then_reload() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), weapon_id=3, clip_size=10, ammo=0, fire_bullets_timer=1.0)
    player.aim_dir = Vec2(1.0, 0.0)

    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(101.0, 100.0)), 0.0, state)

    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 12
    assert set(type_ids) == {0x2D}
    assert player.reload_active
    assert player.reload_timer > 0.0


def test_player_fire_weapon_fire_bullets_uses_fire_bullets_spread_heat_inc_for_pellet_weapons() -> None:
    from crimson.weapons import weapon_entry_for_projectile_type_id

    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), weapon_id=3, clip_size=10, ammo=10, fire_bullets_timer=1.0)
    player.aim_dir = Vec2(1.0, 0.0)

    fire_bullets_weapon = weapon_entry_for_projectile_type_id(int(ProjectileTypeId.FIRE_BULLETS))
    assert fire_bullets_weapon is not None
    assert fire_bullets_weapon.spread_heat_inc is not None

    start_heat = player.spread_heat
    expected = start_heat + float(fire_bullets_weapon.spread_heat_inc) * 1.3

    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(101.0, 100.0)), 0.0, state)

    assert math.isclose(player.spread_heat, expected, abs_tol=1e-9)


def test_player_fire_weapon_fire_bullets_uses_fire_bullets_spread_heat_inc_for_single_pellet_weapons() -> None:
    from crimson.projectiles import ProjectileTypeId
    from crimson.weapons import weapon_entry_for_projectile_type_id

    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), weapon_id=2, clip_size=25, ammo=25, fire_bullets_timer=1.0)
    player.aim_dir = Vec2(1.0, 0.0)

    fire_bullets_weapon = weapon_entry_for_projectile_type_id(int(ProjectileTypeId.FIRE_BULLETS))
    assert fire_bullets_weapon is not None
    assert fire_bullets_weapon.spread_heat_inc is not None

    start_heat = player.spread_heat
    expected = start_heat + float(fire_bullets_weapon.spread_heat_inc) * 1.3

    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(101.0, 100.0)), 0.0, state)

    assert math.isclose(player.spread_heat, expected, abs_tol=1e-9)


def test_player_fire_weapon_shotgun_spawns_pellets() -> None:
    pool = ProjectilePool(size=64)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), weapon_id=3, clip_size=10, ammo=10)
    player.aim_dir = Vec2(1.0, 0.0)

    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(101.0, 100.0)), 0.0, state)

    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 12
    assert set(type_ids) == {3}


def test_player_update_tracks_aim_point() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(10.0, 20.0))
    input_state = PlayerInput(aim=Vec2(123.0, 456.0))

    player_update(player, input_state, 0.1, state)

    assert player.aim == Vec2(123.0, 456.0)


def test_player_fire_weapon_uses_disc_spread_jitter() -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(projectiles=pool)

    seed = 0xBEEF
    state.rng.srand(seed)

    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), weapon_id=1, clip_size=10, ammo=10, spread_heat=0.2)

    aim_x = 200.0
    aim_y = 100.0

    expected_rng = Crand(seed)
    # Weapons with `flags & 0x1` spawn the casing effect before aim jitter, which
    # consumes 4 CRT rand() calls in the native firing path.
    for _ in range(4):
        expected_rng.rand()
    rand_dir = expected_rng.rand()
    rand_mag = expected_rng.rand()

    dx = aim_x - player.pos.x
    dy = aim_y - player.pos.y
    dist = math.hypot(dx, dy)
    max_offset = dist * player.spread_heat * 0.5
    dir_angle = float(rand_dir & 0x1FF) * (math.tau / 512.0)
    mag = float(rand_mag & 0x1FF) * (1.0 / 512.0)
    offset = max_offset * mag
    jitter_x = aim_x + math.cos(dir_angle) * offset
    jitter_y = aim_y + math.sin(dir_angle) * offset
    expected_angle = math.atan2(jitter_y - player.pos.y, jitter_x - player.pos.x) + math.pi / 2.0

    player_fire_weapon(player, PlayerInput(fire_down=True, aim=Vec2(aim_x, aim_y)), 0.0, state)

    projectiles = pool.iter_active()
    assert len(projectiles) == 1
    assert math.isclose(projectiles[0].angle, expected_angle, abs_tol=1e-9)


def test_player_update_hot_tempered_spawns_ring() -> None:
    pool = ProjectilePool(size=16)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), hot_tempered_timer=1.95)
    player.perk_counts[int(PerkId.HOT_TEMPERED)] = 1

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.1, state)

    owner_ids = {int(entry.owner_id) for entry in pool.entries if entry.active}
    assert owner_ids == {-100}
    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 8
    assert type_ids.count(0x0B) == 4
    assert type_ids.count(0x09) == 4


def test_player_update_hot_tempered_converts_to_fire_bullets_when_active() -> None:
    pool = ProjectilePool(size=16)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0), hot_tempered_timer=1.95, fire_bullets_timer=1.0)
    player.perk_counts[int(PerkId.HOT_TEMPERED)] = 1

    player_update(player, PlayerInput(aim=Vec2(101.0, 100.0)), 0.1, state, players=[player])

    owner_ids = {int(entry.owner_id) for entry in pool.entries if entry.active}
    assert owner_ids == {-100}
    type_ids = _active_type_ids(pool)
    assert len(type_ids) == 8
    assert set(type_ids) == {int(ProjectileTypeId.FIRE_BULLETS)}


def test_bonus_apply_registers_hud_slot_and_expires() -> None:
    state = GameplayState()
    player = PlayerState(index=0, pos=Vec2(100.0, 100.0))

    bonus_apply(state, player, BonusId.WEAPON_POWER_UP, amount=3)
    for _ in range(40):
        bonus_hud_update(state, [player], dt=1.0 / 60.0)

    assert any(slot.active and slot.bonus_id == int(BonusId.WEAPON_POWER_UP) for slot in state.bonus_hud.slots)

    state.bonuses.weapon_power_up = 0.0
    for _ in range(60):
        bonus_hud_update(state, [player], dt=1.0 / 60.0)
    assert not any(slot.active and slot.bonus_id == int(BonusId.WEAPON_POWER_UP) for slot in state.bonus_hud.slots)


def test_bonus_apply_shock_chain_spawns_projectile_and_chains() -> None:
    pool = ProjectilePool(size=8)
    state = GameplayState(projectiles=pool)
    player = PlayerState(index=0, pos=Vec2())
    far_y = math.sqrt(100.0 * 100.0 - 50.0 * 50.0)
    creatures = [
        _Creature(pos=Vec2(50.0, 0.0), hp=100.0),
        _Creature(pos=Vec2(80.0, 0.0), hp=100.0),
        _Creature(pos=Vec2(100.0, far_y), hp=100.0),
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

    assert state.shock_chain_links_left == 0x1F
    assert state.shock_chain_projectile_id != first_proj
    assert sum(1 for entry in pool.entries if entry.active) >= 2
    chained = pool.entries[int(state.shock_chain_projectile_id)]
    expected_angle = math.atan2(far_y, 50.0) + math.pi / 2.0
    assert math.isclose(chained.angle, expected_angle, abs_tol=1e-9)
