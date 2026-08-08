from __future__ import annotations

"""
Weapon definitions for the rewrite runtime.

Weapon ids use native 1-based values (e.g. `weapon_id=1` for Pistol).
Projectile `type_id` values route projectile behavior and template lookups.
By native design they reuse the same numeric ids as `WeaponId` for default
cases, with explicit overrides for remapped templates and non-primary paths
(particle/secondary pools).

Use `projectile_type_id_for_weapon_id` for the primary projectile `type_id`.
Weapons that use particle or secondary projectile pools raise `ValueError`.

Reference material:
- `docs/re/static/reference/weapon-table.md`
- `docs/re/static/reference/weapon-id-map.md`
"""

from enum import IntEnum

import msgspec

from grim.sfx_map import SfxId

from .math_parity import f32
from .projectiles.types import ProjectileTemplateId


class WeaponId(IntEnum):
    NONE = 0
    PISTOL = 1
    ASSAULT_RIFLE = 2
    SHOTGUN = 3
    SAWED_OFF_SHOTGUN = 4
    SUBMACHINE_GUN = 5
    GAUSS_GUN = 6
    MEAN_MINIGUN = 7
    FLAMETHROWER = 8
    PLASMA_RIFLE = 9
    MULTI_PLASMA = 10
    PLASMA_MINIGUN = 11
    ROCKET_LAUNCHER = 12
    SEEKER_ROCKETS = 13
    PLASMA_SHOTGUN = 14
    BLOW_TORCH = 15
    HR_FLAMER = 16
    MINI_ROCKET_SWARMERS = 17
    ROCKET_MINIGUN = 18
    PULSE_GUN = 19
    JACKHAMMER = 20
    ION_RIFLE = 21
    ION_MINIGUN = 22
    ION_CANNON = 23
    SHRINKIFIER_5K = 24
    BLADE_GUN = 25
    SPIDER_PLASMA = 26
    EVIL_SCYTHE = 27
    PLASMA_CANNON = 28
    SPLITTER_GUN = 29
    GAUSS_SHOTGUN = 30
    ION_SHOTGUN = 31
    FLAMEBURST = 32
    RAYGUN = 33
    UNUSED_34 = 34
    UNUSED_35 = 35
    UNUSED_36 = 36
    UNUSED_37 = 37
    UNUSED_38 = 38
    UNUSED_39 = 39
    UNUSED_40 = 40
    PLAGUE_SPREADER_GUN = 41
    BUBBLEGUN = 42
    RAINBOW_GUN = 43
    GRIM_WEAPON = 44
    FIRE_BULLETS = 45
    UNUSED_46 = 46
    UNUSED_47 = 47
    UNUSED_48 = 48
    UNUSED_49 = 49
    TRANSMUTATOR = 50
    BLASTER_R_300 = 51
    LIGHTNING_RIFLE = 52
    NUKE_LAUNCHER = 53


class Weapon(msgspec.Struct, frozen=True):
    weapon_id: WeaponId
    name: str
    ammo_class: int | None
    clip_size: int
    shot_cooldown: float
    reload_time: float
    spread_heat_inc: float
    fire_sound: SfxId
    reload_sound: SfxId
    icon_index: int
    flags: int | None
    travel_budget: int
    damage_scale: float
    pellet_count: int

WEAPON_TABLE = [
    Weapon(
        weapon_id=WeaponId.PISTOL,
        name="Pistol",
        ammo_class=0,
        clip_size=12,
        shot_cooldown=0.7117,
        reload_time=1.2,
        spread_heat_inc=0.22,
        fire_sound=SfxId.PISTOL_FIRE,
        reload_sound=SfxId.PISTOL_RELOAD,
        icon_index=0,
        flags=5,
        travel_budget=55,
        damage_scale=4.1,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.ASSAULT_RIFLE,
        name="Assault Rifle",
        ammo_class=0,
        clip_size=25,
        shot_cooldown=0.117,
        reload_time=1.2,
        spread_heat_inc=0.09,
        fire_sound=SfxId.AUTORIFLE_FIRE,
        reload_sound=SfxId.AUTORIFLE_RELOAD,
        icon_index=1,
        flags=1,
        travel_budget=50,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.SHOTGUN,
        name="Shotgun",
        ammo_class=0,
        clip_size=12,
        shot_cooldown=0.85,
        reload_time=1.9,
        spread_heat_inc=0.27,
        fire_sound=SfxId.SHOTGUN_FIRE,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=2,
        flags=1,
        travel_budget=60,
        damage_scale=1.2,
        pellet_count=12,
    ),
    Weapon(
        weapon_id=WeaponId.SAWED_OFF_SHOTGUN,
        name='Sawed-off Shotgun',
        ammo_class=0,
        clip_size=12,
        shot_cooldown=0.87,
        reload_time=1.9,
        spread_heat_inc=0.13,
        fire_sound=SfxId.SHOTGUN_FIRE,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=3,
        flags=1,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=12,
    ),
    Weapon(
        weapon_id=WeaponId.SUBMACHINE_GUN,
        name='Submachine Gun',
        ammo_class=0,
        clip_size=30,
        shot_cooldown=0.088117,
        reload_time=1.2,
        spread_heat_inc=0.082,
        fire_sound=SfxId.HRPM_FIRE,
        reload_sound=SfxId.AUTORIFLE_RELOAD,
        icon_index=4,
        flags=5,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.GAUSS_GUN,
        name='Gauss Gun',
        ammo_class=0,
        clip_size=6,
        shot_cooldown=0.6,
        reload_time=1.6,
        spread_heat_inc=0.42,
        fire_sound=SfxId.GAUSS_FIRE,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=5,
        flags=1,
        travel_budget=215,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.MEAN_MINIGUN,
        name='Mean Minigun',
        ammo_class=0,
        clip_size=120,
        shot_cooldown=0.09,
        reload_time=4.0,
        spread_heat_inc=0.062,
        fire_sound=SfxId.AUTORIFLE_FIRE,
        reload_sound=SfxId.AUTORIFLE_RELOAD,
        icon_index=6,
        flags=3,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.FLAMETHROWER,
        name='Flamethrower',
        ammo_class=1,
        clip_size=30,
        shot_cooldown=0.008113,
        reload_time=2.0,
        spread_heat_inc=0.015,
        fire_sound=SfxId.FLAMER_FIRE_01,
        reload_sound=SfxId.AUTORIFLE_RELOAD,
        icon_index=7,
        flags=8,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.PLASMA_RIFLE,
        name='Plasma Rifle',
        ammo_class=0,
        clip_size=20,
        shot_cooldown=0.2908117,
        reload_time=1.2,
        spread_heat_inc=0.182,
        fire_sound=SfxId.SHOCK_FIRE,
        reload_sound=SfxId.AUTORIFLE_RELOAD,
        icon_index=8,
        flags=None,
        travel_budget=30,
        damage_scale=5.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.MULTI_PLASMA,
        name='Multi-Plasma',
        ammo_class=0,
        clip_size=8,
        shot_cooldown=0.6208117,
        reload_time=1.4,
        spread_heat_inc=0.32,
        fire_sound=SfxId.SHOCK_FIRE,
        reload_sound=SfxId.AUTORIFLE_RELOAD,
        icon_index=9,
        flags=None,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=3,
    ),
    Weapon(
        weapon_id=WeaponId.PLASMA_MINIGUN,
        name='Plasma Minigun',
        ammo_class=0,
        clip_size=30,
        shot_cooldown=0.11,
        reload_time=1.3,
        spread_heat_inc=0.097,
        fire_sound=SfxId.PLASMAMINIGUN_FIRE,
        reload_sound=SfxId.AUTORIFLE_RELOAD,
        icon_index=10,
        flags=None,
        travel_budget=35,
        damage_scale=2.1,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.ROCKET_LAUNCHER,
        name='Rocket Launcher',
        ammo_class=2,
        clip_size=5,
        shot_cooldown=0.7408117,
        reload_time=1.2,
        spread_heat_inc=0.42,
        fire_sound=SfxId.ROCKET_FIRE,
        reload_sound=SfxId.AUTORIFLE_RELOAD_ALT,
        icon_index=11,
        flags=8,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.SEEKER_ROCKETS,
        name='Seeker Rockets',
        ammo_class=2,
        clip_size=8,
        shot_cooldown=0.3108117,
        reload_time=1.2,
        spread_heat_inc=0.32,
        fire_sound=SfxId.ROCKET_FIRE,
        reload_sound=SfxId.AUTORIFLE_RELOAD_ALT,
        icon_index=12,
        flags=8,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.PLASMA_SHOTGUN,
        name='Plasma Shotgun',
        ammo_class=0,
        clip_size=8,
        shot_cooldown=0.48,
        reload_time=3.1,
        spread_heat_inc=0.11,
        fire_sound=SfxId.PLASMASHOTGUN_FIRE,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=13,
        flags=None,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=14,
    ),
    Weapon(
        weapon_id=WeaponId.BLOW_TORCH,
        name='Blow Torch',
        ammo_class=1,
        clip_size=30,
        shot_cooldown=0.006113,
        reload_time=1.5,
        spread_heat_inc=0.01,
        fire_sound=SfxId.FLAMER_FIRE_01,
        reload_sound=SfxId.AUTORIFLE_RELOAD,
        icon_index=14,
        flags=8,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.HR_FLAMER,
        name='HR Flamer',
        ammo_class=1,
        clip_size=30,
        shot_cooldown=0.0085,
        reload_time=1.8,
        spread_heat_inc=0.01,
        fire_sound=SfxId.FLAMER_FIRE_01,
        reload_sound=SfxId.AUTORIFLE_RELOAD,
        icon_index=15,
        flags=8,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.MINI_ROCKET_SWARMERS,
        name='Mini-Rocket Swarmers',
        ammo_class=2,
        clip_size=5,
        shot_cooldown=1.8,
        reload_time=1.8,
        spread_heat_inc=0.12,
        fire_sound=SfxId.ROCKET_FIRE,
        reload_sound=SfxId.AUTORIFLE_RELOAD_ALT,
        icon_index=16,
        flags=8,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.ROCKET_MINIGUN,
        name='Rocket Minigun',
        ammo_class=2,
        clip_size=16,
        shot_cooldown=0.12,
        reload_time=1.8,
        spread_heat_inc=0.12,
        fire_sound=SfxId.ROCKETMINI_FIRE,
        reload_sound=SfxId.AUTORIFLE_RELOAD_ALT,
        icon_index=17,
        flags=8,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.PULSE_GUN,
        name='Pulse Gun',
        ammo_class=3,
        clip_size=16,
        shot_cooldown=0.1,
        reload_time=0.1,
        spread_heat_inc=0.0,
        fire_sound=SfxId.PULSE_FIRE,
        reload_sound=SfxId.AUTORIFLE_RELOAD,
        icon_index=18,
        flags=8,
        travel_budget=20,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.JACKHAMMER,
        name='Jackhammer',
        ammo_class=0,
        clip_size=16,
        shot_cooldown=0.14,
        reload_time=3.0,
        spread_heat_inc=0.16,
        fire_sound=SfxId.SHOTGUN_FIRE,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=19,
        flags=1,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=4,
    ),
    Weapon(
        weapon_id=WeaponId.ION_RIFLE,
        name='Ion Rifle',
        ammo_class=4,
        clip_size=8,
        shot_cooldown=0.4,
        reload_time=1.35,
        spread_heat_inc=0.112,
        fire_sound=SfxId.SHOCK_FIRE_ALT,
        reload_sound=SfxId.SHOCK_RELOAD,
        icon_index=20,
        flags=8,
        travel_budget=15,
        damage_scale=3.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.ION_MINIGUN,
        name='Ion Minigun',
        ammo_class=4,
        clip_size=20,
        shot_cooldown=0.1,
        reload_time=1.8,
        spread_heat_inc=0.09,
        fire_sound=SfxId.SHOCKMINIGUN_FIRE,
        reload_sound=SfxId.SHOCK_RELOAD,
        icon_index=21,
        flags=8,
        travel_budget=20,
        damage_scale=1.4,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.ION_CANNON,
        name='Ion Cannon',
        ammo_class=4,
        clip_size=3,
        shot_cooldown=1.0,
        reload_time=3.0,
        spread_heat_inc=0.68,
        fire_sound=SfxId.SHOCK_FIRE_ALT,
        reload_sound=SfxId.SHOCK_RELOAD,
        icon_index=22,
        flags=None,
        travel_budget=10,
        damage_scale=16.7,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.SHRINKIFIER_5K,
        name='Shrinkifier 5k',
        ammo_class=0,
        clip_size=8,
        shot_cooldown=0.21,
        reload_time=1.22,
        spread_heat_inc=0.04,
        fire_sound=SfxId.SHOCK_FIRE_ALT,
        reload_sound=SfxId.SHOCK_RELOAD,
        icon_index=23,
        flags=8,
        travel_budget=45,
        damage_scale=0.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.BLADE_GUN,
        name='Blade Gun',
        ammo_class=0,
        clip_size=6,
        shot_cooldown=0.35,
        reload_time=3.5,
        spread_heat_inc=0.04,
        fire_sound=SfxId.SHOCK_FIRE_ALT,
        reload_sound=SfxId.SHOCK_RELOAD,
        icon_index=24,
        flags=8,
        travel_budget=20,
        damage_scale=11.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.SPIDER_PLASMA,
        name='Spider Plasma',
        ammo_class=0,
        clip_size=5,
        shot_cooldown=0.2,
        reload_time=1.2,
        spread_heat_inc=0.04,
        fire_sound=SfxId.BLOODSPILL_01,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=25,
        flags=8,
        travel_budget=10,
        damage_scale=0.5,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.EVIL_SCYTHE,
        name='Evil Scythe',
        ammo_class=4,
        clip_size=3,
        shot_cooldown=1.0,
        reload_time=3.0,
        spread_heat_inc=0.68,
        fire_sound=SfxId.SHOCK_FIRE_ALT,
        reload_sound=SfxId.SHOCK_RELOAD,
        icon_index=25,
        flags=None,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.PLASMA_CANNON,
        name='Plasma Cannon',
        ammo_class=0,
        clip_size=3,
        shot_cooldown=0.9,
        reload_time=2.7,
        spread_heat_inc=0.6,
        fire_sound=SfxId.SHOCK_FIRE,
        reload_sound=SfxId.SHOCK_RELOAD,
        icon_index=25,
        flags=None,
        travel_budget=10,
        damage_scale=28.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.SPLITTER_GUN,
        name='Splitter Gun',
        ammo_class=0,
        clip_size=6,
        shot_cooldown=0.7,
        reload_time=2.2,
        spread_heat_inc=0.28,
        fire_sound=SfxId.SHOCK_FIRE_ALT,
        reload_sound=SfxId.SHOCK_RELOAD,
        icon_index=28,
        flags=None,
        travel_budget=30,
        damage_scale=6.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.GAUSS_SHOTGUN,
        name='Gauss Shotgun',
        ammo_class=0,
        clip_size=4,
        shot_cooldown=1.05,
        reload_time=2.1,
        spread_heat_inc=0.27,
        fire_sound=SfxId.GAUSS_FIRE,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=30,
        flags=1,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.ION_SHOTGUN,
        name='Ion Shotgun',
        ammo_class=4,
        clip_size=10,
        shot_cooldown=0.85,
        reload_time=1.9,
        spread_heat_inc=0.27,
        fire_sound=SfxId.SHOCK_FIRE_ALT,
        reload_sound=SfxId.SHOCK_RELOAD,
        icon_index=31,
        flags=1,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=8,
    ),
    Weapon(
        weapon_id=WeaponId.FLAMEBURST,
        name='Flameburst',
        ammo_class=4,
        clip_size=60,
        shot_cooldown=0.02,
        reload_time=3.0,
        spread_heat_inc=0.18,
        fire_sound=SfxId.FLAMER_FIRE_01,
        reload_sound=SfxId.SHOCK_RELOAD,
        icon_index=29,
        flags=None,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.RAYGUN,
        name='RayGun',
        ammo_class=4,
        clip_size=12,
        shot_cooldown=0.7,
        reload_time=2.0,
        spread_heat_inc=0.38,
        fire_sound=SfxId.SHOCK_FIRE_ALT,
        reload_sound=SfxId.SHOCK_RELOAD,
        icon_index=30,
        flags=None,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.PLAGUE_SPREADER_GUN,
        name='Plague Sphreader Gun',
        ammo_class=None,
        clip_size=5,
        shot_cooldown=0.2,
        reload_time=1.2,
        spread_heat_inc=0.04,
        fire_sound=SfxId.BLOODSPILL_01,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=40,
        flags=8,
        travel_budget=15,
        damage_scale=0.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.BUBBLEGUN,
        name='Bubblegun',
        ammo_class=None,
        clip_size=15,
        shot_cooldown=0.1613,
        reload_time=1.2,
        spread_heat_inc=0.05,
        fire_sound=SfxId.BLOODSPILL_01,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=41,
        flags=8,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.RAINBOW_GUN,
        name='Rainbow Gun',
        ammo_class=None,
        clip_size=10,
        shot_cooldown=0.2,
        reload_time=1.2,
        spread_heat_inc=0.09,
        fire_sound=SfxId.BLOODSPILL_01,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=42,
        flags=8,
        travel_budget=10,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.GRIM_WEAPON,
        name='Grim Weapon',
        ammo_class=None,
        clip_size=3,
        shot_cooldown=0.5,
        reload_time=1.2,
        spread_heat_inc=0.4,
        fire_sound=SfxId.BLOODSPILL_01,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=43,
        flags=None,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.FIRE_BULLETS,
        name='Fire bullets',
        ammo_class=None,
        clip_size=112,
        shot_cooldown=0.14,
        reload_time=1.2,
        spread_heat_inc=0.22,
        fire_sound=SfxId.AUTORIFLE_FIRE,
        reload_sound=SfxId.PISTOL_RELOAD,
        icon_index=44,
        flags=1,
        travel_budget=60,
        damage_scale=0.25,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.TRANSMUTATOR,
        name='Transmutator',
        ammo_class=None,
        clip_size=50,
        shot_cooldown=0.04,
        reload_time=5.0,
        spread_heat_inc=0.04,
        fire_sound=SfxId.BLOODSPILL_01,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=49,
        flags=9,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.BLASTER_R_300,
        name='Blaster R-300',
        ammo_class=None,
        clip_size=20,
        shot_cooldown=0.08,
        reload_time=2.0,
        spread_heat_inc=0.05,
        fire_sound=SfxId.SHOCK_FIRE,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=50,
        flags=9,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.LIGHTNING_RIFLE,
        name='Lighting Rifle',
        ammo_class=None,
        clip_size=500,
        shot_cooldown=4.0,
        reload_time=8.0,
        spread_heat_inc=1.0,
        fire_sound=SfxId.EXPLOSION_LARGE,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=51,
        flags=8,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=WeaponId.NUKE_LAUNCHER,
        name='Nuke Launcher',
        ammo_class=None,
        clip_size=1,
        shot_cooldown=4.0,
        reload_time=8.0,
        spread_heat_inc=1.0,
        fire_sound=SfxId.EXPLOSION_LARGE,
        reload_sound=SfxId.SHOTGUN_RELOAD,
        icon_index=52,
        flags=8,
        travel_budget=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
]

# The native weapon table stores float32 fields; quantize the transcribed
# decimal literals so raw state (reload timers, cooldowns) matches captures.
WEAPON_TABLE = [
    msgspec.structs.replace(
        entry,
        shot_cooldown=float(f32(entry.shot_cooldown)),
        reload_time=float(f32(entry.reload_time)),
        spread_heat_inc=float(f32(entry.spread_heat_inc)),
        damage_scale=float(f32(entry.damage_scale)),
    )
    for entry in WEAPON_TABLE
]

WEAPON_BY_ID: dict[WeaponId, Weapon] = {entry.weapon_id: entry for entry in WEAPON_TABLE}

_WEAPON_FIXED_NAMES: dict[WeaponId, str] = {
    WeaponId.PLAGUE_SPREADER_GUN: "Plague Spreader Gun",
    WeaponId.LIGHTNING_RIFLE: "Lightning Rifle",
    WeaponId.FIRE_BULLETS: "Fire Bullets",
}


def weapon_display_name(weapon_id: WeaponId, *, preserve_bugs: bool = False) -> str:
    try:
        entry = WEAPON_BY_ID[weapon_id]
    except KeyError:
        return f"weapon_{weapon_id}"
    name = entry.name
    if bool(preserve_bugs):
        return str(name)
    fixed = _WEAPON_FIXED_NAMES.get(weapon_id)
    if fixed is not None:
        return fixed
    return str(name)


PROJECTILE_TEMPLATE_OVERRIDES: dict[WeaponId, tuple[ProjectileTemplateId, ...]] = {
    # Derived from native `player_fire_weapon` behavior.
    # Omitted keys use the native default `type_id == weapon_id`.
    # Empty tuples are explicit non-primary projectile paths.
    WeaponId.SAWED_OFF_SHOTGUN: (ProjectileTemplateId.SHOTGUN,),
    WeaponId.MEAN_MINIGUN: (ProjectileTemplateId.PISTOL,),
    WeaponId.FLAMETHROWER: (),
    WeaponId.MULTI_PLASMA: (ProjectileTemplateId.PLASMA_RIFLE, ProjectileTemplateId.PLASMA_MINIGUN),
    WeaponId.ROCKET_LAUNCHER: (),
    WeaponId.SEEKER_ROCKETS: (),
    WeaponId.PLASMA_SHOTGUN: (ProjectileTemplateId.PLASMA_MINIGUN,),
    WeaponId.BLOW_TORCH: (),
    WeaponId.HR_FLAMER: (),
    WeaponId.MINI_ROCKET_SWARMERS: (),
    WeaponId.ROCKET_MINIGUN: (),
    WeaponId.JACKHAMMER: (ProjectileTemplateId.SHOTGUN,),
    WeaponId.GAUSS_SHOTGUN: (ProjectileTemplateId.GAUSS_GUN,),
    WeaponId.ION_SHOTGUN: (ProjectileTemplateId.ION_MINIGUN,),
    WeaponId.BUBBLEGUN: (),
}

def weapon_entry_for_projectile_type_id(type_id: ProjectileTemplateId) -> Weapon:
    """
    Native `projectile_spawn` indexes weapon metadata by projectile type id.
    The type id is the weapon id used as the projectile stats template.
    """
    return WEAPON_BY_ID[WeaponId(type_id)]


def projectile_type_id_for_weapon_id(weapon_id: WeaponId) -> ProjectileTemplateId:
    """Return the primary projectile type for a weapon that uses the main pool."""

    type_ids = PROJECTILE_TEMPLATE_OVERRIDES.get(weapon_id)
    if type_ids is not None:
        if not type_ids:
            raise ValueError(f"weapon has no primary projectile type: {int(weapon_id)}")
        return type_ids[0]
    try:
        return ProjectileTemplateId(weapon_id)
    except ValueError as exc:
        raise ValueError(f"weapon has no primary projectile type: {int(weapon_id)}") from exc
