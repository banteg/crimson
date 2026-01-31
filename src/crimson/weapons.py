from __future__ import annotations

"""
Weapon definitions for the rewrite runtime.

This file is **manually maintained** (do not auto-generate).

It was originally seeded from `weapon_table_init` (`FUN_004519b0`) and the
rewrite now uses the **native 1-based weapon ids** (e.g. pistol is
`weapon_id=1`). In the native code, projectile `type_id` values passed into
`projectile_spawn` are **weapon table indices** (same numeric domain as weapon
ids). They are **not** a 1:1 mapping: multiple weapons can share a projectile
type id (e.g. Sawed-off and Jackhammer use the Shotgun template), and some
weapons bypass `projectile_spawn` entirely (particles / secondary pool).

Use `projectile_type_id_from_weapon_id` for the primary projectile `type_id`
(or `None` for non-projectile weapons), and `projectile_type_ids_from_weapon_id`
when you need the full set.

Reference material:
- `docs/weapon-table.md` (native struct + fields)
- `docs/weapon-id-map.md` (native ids + names)
"""

from dataclasses import dataclass
from enum import IntEnum

MANUALLY_MAINTAINED = True


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
    UNKNOWN_34 = 34
    UNKNOWN_35 = 35
    UNKNOWN_36 = 36
    UNKNOWN_37 = 37
    UNKNOWN_38 = 38
    UNKNOWN_39 = 39
    UNKNOWN_40 = 40
    PLAGUE_SPHREADER_GUN = 41
    BUBBLEGUN = 42
    RAINBOW_GUN = 43
    GRIM_WEAPON = 44
    FIRE_BULLETS = 45
    UNKNOWN_46 = 46
    UNKNOWN_47 = 47
    UNKNOWN_48 = 48
    UNKNOWN_49 = 49
    TRANSMUTATOR = 50
    BLASTER_R_300 = 51
    LIGHTING_RIFLE = 52
    NUKE_LAUNCHER = 53


@dataclass(frozen=True)
class Weapon:
    weapon_id: int
    name: str | None
    ammo_class: int | None
    clip_size: int | None
    shot_cooldown: float | None
    reload_time: float | None
    spread_heat_inc: float | None
    fire_sound: str | None
    reload_sound: str | None
    icon_index: int | None
    flags: int | None
    projectile_meta: int | None
    damage_scale: float | None
    pellet_count: int | None


WEAPON_TABLE = [
    Weapon(
        weapon_id=1,
        name='Pistol',
        ammo_class=0,
        clip_size=12,
        shot_cooldown=0.7117000222206116,
        reload_time=1.2000000476837158,
        spread_heat_inc=0.2199999988079071,
        fire_sound='sfx_pistol_fire',
        reload_sound='sfx_pistol_reload',
        icon_index=0,
        flags=5,
        projectile_meta=55,
        damage_scale=4.099999904632568,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=2,
        name='Assault Rifle',
        ammo_class=0,
        clip_size=25,
        shot_cooldown=0.11699999868869781,
        reload_time=1.2000000476837158,
        spread_heat_inc=0.09000000357627869,
        fire_sound='sfx_autorifle_fire',
        reload_sound='sfx_autorifle_reload',
        icon_index=1,
        flags=1,
        projectile_meta=50,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=3,
        name='Shotgun',
        ammo_class=0,
        clip_size=12,
        shot_cooldown=0.8500000238418579,
        reload_time=1.899999976158142,
        spread_heat_inc=0.27000001072883606,
        fire_sound='sfx_shotgun_fire',
        reload_sound='_DAT_004d93bc',
        icon_index=2,
        flags=1,
        projectile_meta=60,
        damage_scale=1.2000000476837158,
        pellet_count=12,
    ),
    Weapon(
        weapon_id=4,
        name='Sawed-off Shotgun',
        ammo_class=0,
        clip_size=12,
        shot_cooldown=0.8700000047683716,
        reload_time=1.899999976158142,
        spread_heat_inc=0.12999999523162842,
        fire_sound='_DAT_004d8434',
        reload_sound='_DAT_004d93bc',
        icon_index=3,
        flags=1,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=12,
    ),
    Weapon(
        weapon_id=5,
        name='Submachine Gun',
        ammo_class=0,
        clip_size=30,
        shot_cooldown=0.08811700344085693,
        reload_time=1.2000000476837158,
        spread_heat_inc=0.0820000022649765,
        fire_sound='sfx_hrpm_fire',
        reload_sound='_DAT_004d83c0',
        icon_index=4,
        flags=5,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=6,
        name='Gauss Gun',
        ammo_class=0,
        clip_size=6,
        shot_cooldown=0.6000000238418579,
        reload_time=1.600000023841858,
        spread_heat_inc=0.41999998688697815,
        fire_sound='sfx_gauss_fire',
        reload_sound='_DAT_004d93bc',
        icon_index=5,
        flags=1,
        projectile_meta=215,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=7,
        name='Mean Minigun',
        ammo_class=0,
        clip_size=120,
        shot_cooldown=0.09000000357627869,
        reload_time=4.0,
        spread_heat_inc=0.06199999898672104,
        fire_sound='sfx_autorifle_fire',
        reload_sound='_DAT_004d83c0',
        icon_index=6,
        flags=3,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=8,
        name='Flamethrower',
        ammo_class=1,
        clip_size=30,
        shot_cooldown=0.008112999610602856,
        reload_time=2.0,
        spread_heat_inc=0.014999999664723873,
        fire_sound='sfx_flamer_fire_01',
        reload_sound='_DAT_004d83c0',
        icon_index=7,
        flags=8,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=9,
        name='Plasma Rifle',
        ammo_class=0,
        clip_size=20,
        shot_cooldown=0.290811687707901,
        reload_time=1.2000000476837158,
        spread_heat_inc=0.18199999630451202,
        fire_sound='sfx_shock_fire',
        reload_sound='_DAT_004d83c0',
        icon_index=8,
        flags=None,
        projectile_meta=30,
        damage_scale=5.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=10,
        name='Multi-Plasma',
        ammo_class=0,
        clip_size=8,
        shot_cooldown=0.6208117008209229,
        reload_time=1.399999976158142,
        spread_heat_inc=0.3199999928474426,
        fire_sound='sfx_shock_fire',
        reload_sound='_DAT_004d83c0',
        icon_index=9,
        flags=None,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=3,
    ),
    Weapon(
        weapon_id=11,
        name='Plasma Minigun',
        ammo_class=0,
        clip_size=30,
        shot_cooldown=0.10999999940395355,
        reload_time=1.2999999523162842,
        spread_heat_inc=0.09700000286102295,
        fire_sound='sfx_plasmaminigun_fire',
        reload_sound='_DAT_004d83c0',
        icon_index=10,
        flags=None,
        projectile_meta=35,
        damage_scale=2.0999999046325684,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=12,
        name='Rocket Launcher',
        ammo_class=2,
        clip_size=5,
        shot_cooldown=0.7408117055892944,
        reload_time=1.2000000476837158,
        spread_heat_inc=0.41999998688697815,
        fire_sound='sfx_rocket_fire',
        reload_sound='sfx_autorifle_reload_alt',
        icon_index=11,
        flags=8,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=13,
        name='Seeker Rockets',
        ammo_class=2,
        clip_size=8,
        shot_cooldown=0.31081169843673706,
        reload_time=1.2000000476837158,
        spread_heat_inc=0.3199999928474426,
        fire_sound='sfx_rocket_fire',
        reload_sound='sfx_autorifle_reload_alt',
        icon_index=12,
        flags=8,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=14,
        name='Plasma Shotgun',
        ammo_class=0,
        clip_size=8,
        shot_cooldown=0.47999998927116394,
        reload_time=3.0999999046325684,
        spread_heat_inc=0.10999999940395355,
        fire_sound='sfx_plasmashotgun_fire',
        reload_sound='_DAT_004d93bc',
        icon_index=13,
        flags=None,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=14,
    ),
    Weapon(
        weapon_id=15,
        name='Blow Torch',
        ammo_class=1,
        clip_size=30,
        shot_cooldown=0.006113000214099884,
        reload_time=1.5,
        spread_heat_inc=0.009999999776482582,
        fire_sound='sfx_flamer_fire_01',
        reload_sound='_DAT_004d83c0',
        icon_index=14,
        flags=8,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=16,
        name='HR Flamer',
        ammo_class=1,
        clip_size=30,
        shot_cooldown=0.008500000461935997,
        reload_time=1.7999999523162842,
        spread_heat_inc=0.009999999776482582,
        fire_sound='sfx_flamer_fire_01',
        reload_sound='_DAT_004d83c0',
        icon_index=15,
        flags=8,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=17,
        name='Mini-Rocket Swarmers',
        ammo_class=2,
        clip_size=5,
        shot_cooldown=1.7999999523162842,
        reload_time=1.7999999523162842,
        spread_heat_inc=0.11999999731779099,
        fire_sound='sfx_rocket_fire',
        reload_sound='sfx_autorifle_reload_alt',
        icon_index=16,
        flags=8,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=18,
        name='Rocket Minigun',
        ammo_class=2,
        clip_size=16,
        shot_cooldown=0.11999999731779099,
        reload_time=1.7999999523162842,
        spread_heat_inc=0.11999999731779099,
        fire_sound='sfx_rocketmini_fire',
        reload_sound='sfx_autorifle_reload_alt',
        icon_index=17,
        flags=8,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=19,
        name='Pulse Gun',
        ammo_class=3,
        clip_size=16,
        shot_cooldown=0.10000000149011612,
        reload_time=0.10000000149011612,
        spread_heat_inc=0.0,
        fire_sound='sfx_pulse_fire',
        reload_sound='sfx_autorifle_reload',
        icon_index=18,
        flags=8,
        projectile_meta=20,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=20,
        name='Jackhammer',
        ammo_class=0,
        clip_size=16,
        shot_cooldown=0.14000000059604645,
        reload_time=3.0,
        spread_heat_inc=0.1599999964237213,
        fire_sound='sfx_shotgun_fire',
        reload_sound='_DAT_004d93bc',
        icon_index=19,
        flags=1,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=4,
    ),
    Weapon(
        weapon_id=21,
        name='Ion Rifle',
        ammo_class=4,
        clip_size=8,
        shot_cooldown=0.4000000059604645,
        reload_time=1.350000023841858,
        spread_heat_inc=0.1120000034570694,
        fire_sound='sfx_shock_fire_alt',
        reload_sound='_DAT_004d86a8',
        icon_index=20,
        flags=8,
        projectile_meta=15,
        damage_scale=3.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=22,
        name='Ion Minigun',
        ammo_class=4,
        clip_size=20,
        shot_cooldown=0.10000000149011612,
        reload_time=1.7999999523162842,
        spread_heat_inc=0.09000000357627869,
        fire_sound='sfx_shockminigun_fire',
        reload_sound='_DAT_004d86a8',
        icon_index=21,
        flags=8,
        projectile_meta=20,
        damage_scale=1.399999976158142,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=23,
        name='Ion Cannon',
        ammo_class=4,
        clip_size=3,
        shot_cooldown=1.0,
        reload_time=3.0,
        spread_heat_inc=0.6800000071525574,
        fire_sound='sfx_shock_fire_alt',
        reload_sound='_DAT_004d86a8',
        icon_index=22,
        flags=None,
        projectile_meta=10,
        damage_scale=16.700000762939453,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=24,
        name='Shrinkifier 5k',
        ammo_class=0,
        clip_size=8,
        shot_cooldown=0.20999999344348907,
        reload_time=1.2200000286102295,
        spread_heat_inc=0.03999999910593033,
        fire_sound='sfx_shock_fire_alt',
        reload_sound='_DAT_004d86a8',
        icon_index=23,
        flags=8,
        projectile_meta=45,
        damage_scale=0.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=25,
        name='Blade Gun',
        ammo_class=0,
        clip_size=6,
        shot_cooldown=0.3499999940395355,
        reload_time=3.5,
        spread_heat_inc=0.03999999910593033,
        fire_sound='sfx_shock_fire_alt',
        reload_sound='sfx_shock_reload',
        icon_index=24,
        flags=8,
        projectile_meta=20,
        damage_scale=11.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=26,
        name='Spider Plasma',
        ammo_class=0,
        clip_size=5,
        shot_cooldown=0.20000000298023224,
        reload_time=1.2000000476837158,
        spread_heat_inc=0.03999999910593033,
        fire_sound='_DAT_004d92bc',
        reload_sound='_DAT_004d93bc',
        icon_index=25,
        flags=8,
        projectile_meta=10,
        damage_scale=0.5,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=27,
        name='Evil Scythe',
        ammo_class=4,
        clip_size=3,
        shot_cooldown=1.0,
        reload_time=3.0,
        spread_heat_inc=0.6800000071525574,
        fire_sound='sfx_shock_fire_alt',
        reload_sound='_DAT_004d86a8',
        icon_index=25,
        flags=None,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=28,
        name='Plasma Cannon',
        ammo_class=0,
        clip_size=3,
        shot_cooldown=0.8999999761581421,
        reload_time=2.700000047683716,
        spread_heat_inc=0.6000000238418579,
        fire_sound='sfx_shock_fire',
        reload_sound='_DAT_004d86a8',
        icon_index=25,
        flags=None,
        projectile_meta=10,
        damage_scale=28.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=29,
        name='Splitter Gun',
        ammo_class=0,
        clip_size=6,
        shot_cooldown=0.699999988079071,
        reload_time=2.200000047683716,
        spread_heat_inc=0.2800000011920929,
        fire_sound='sfx_shock_fire_alt',
        reload_sound='_DAT_004d86a8',
        icon_index=28,
        flags=None,
        projectile_meta=30,
        damage_scale=6.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=30,
        name='Gauss Shotgun',
        ammo_class=0,
        clip_size=4,
        shot_cooldown=1.0499999523162842,
        reload_time=2.0999999046325684,
        spread_heat_inc=0.27000001072883606,
        fire_sound='sfx_gauss_fire',
        reload_sound='_DAT_004d93bc',
        icon_index=30,
        flags=1,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=31,
        name='Ion Shotgun',
        ammo_class=4,
        clip_size=10,
        shot_cooldown=0.8500000238418579,
        reload_time=1.899999976158142,
        spread_heat_inc=0.27000001072883606,
        fire_sound='sfx_shock_fire_alt',
        reload_sound='_DAT_004d86a8',
        icon_index=31,
        flags=1,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=8,
    ),
    Weapon(
        weapon_id=32,
        name='Flameburst',
        ammo_class=4,
        clip_size=60,
        shot_cooldown=0.019999999552965164,
        reload_time=3.0,
        spread_heat_inc=0.18000000715255737,
        fire_sound='sfx_flamer_fire_01',
        reload_sound='_DAT_004d86a8',
        icon_index=29,
        flags=None,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=33,
        name='RayGun',
        ammo_class=4,
        clip_size=12,
        shot_cooldown=0.699999988079071,
        reload_time=2.0,
        spread_heat_inc=0.3799999952316284,
        fire_sound='sfx_shock_fire_alt',
        reload_sound='_DAT_004d86a8',
        icon_index=30,
        flags=None,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=41,
        name='Plague Sphreader Gun',
        ammo_class=None,
        clip_size=5,
        shot_cooldown=0.20000000298023224,
        reload_time=1.2000000476837158,
        spread_heat_inc=0.03999999910593033,
        fire_sound='sfx_bloodspill_01',
        reload_sound='_DAT_004d93bc',
        icon_index=40,
        flags=8,
        projectile_meta=15,
        damage_scale=0.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=42,
        name='Bubblegun',
        ammo_class=None,
        clip_size=15,
        shot_cooldown=0.16130000352859497,
        reload_time=1.2000000476837158,
        spread_heat_inc=0.05000000074505806,
        fire_sound='_DAT_004d92bc',
        reload_sound='_DAT_004d93bc',
        icon_index=41,
        flags=8,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=43,
        name='Rainbow Gun',
        ammo_class=None,
        clip_size=10,
        shot_cooldown=0.20000000298023224,
        reload_time=1.2000000476837158,
        spread_heat_inc=0.09000000357627869,
        fire_sound='_DAT_004d92bc',
        reload_sound='_DAT_004d93bc',
        icon_index=42,
        flags=8,
        projectile_meta=10,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=44,
        name='Grim Weapon',
        ammo_class=None,
        clip_size=3,
        shot_cooldown=0.5,
        reload_time=1.2000000476837158,
        spread_heat_inc=0.4000000059604645,
        fire_sound='_DAT_004d92bc',
        reload_sound='_DAT_004d93bc',
        icon_index=43,
        flags=None,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=45,
        name='Fire bullets',
        ammo_class=None,
        clip_size=112,
        shot_cooldown=0.14000000059604645,
        reload_time=1.2000000476837158,
        spread_heat_inc=0.2199999988079071,
        fire_sound='_DAT_004d7b7c',
        reload_sound='sfx_pistol_reload',
        icon_index=44,
        flags=1,
        projectile_meta=60,
        damage_scale=0.25,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=50,
        name='Transmutator',
        ammo_class=None,
        clip_size=50,
        shot_cooldown=0.03999999910593033,
        reload_time=5.0,
        spread_heat_inc=0.03999999910593033,
        fire_sound='sfx_bloodspill_01',
        reload_sound='_DAT_004d93bc',
        icon_index=49,
        flags=9,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=51,
        name='Blaster R-300',
        ammo_class=None,
        clip_size=20,
        shot_cooldown=0.07999999821186066,
        reload_time=2.0,
        spread_heat_inc=0.05000000074505806,
        fire_sound='sfx_shock_fire',
        reload_sound='_DAT_004d93bc',
        icon_index=50,
        flags=9,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=52,
        name='Lighting Rifle',
        ammo_class=None,
        clip_size=500,
        shot_cooldown=4.0,
        reload_time=8.0,
        spread_heat_inc=1.0,
        fire_sound='sfx_explosion_large',
        reload_sound='sfx_shotgun_reload',
        icon_index=51,
        flags=8,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
    Weapon(
        weapon_id=53,
        name='Nuke Launcher',
        ammo_class=None,
        clip_size=1,
        shot_cooldown=4.0,
        reload_time=8.0,
        spread_heat_inc=1.0,
        fire_sound='_DAT_004d93b4',
        reload_sound='_DAT_004d93bc',
        icon_index=52,
        flags=8,
        projectile_meta=45,
        damage_scale=1.0,
        pellet_count=1,
    ),
]

WEAPON_BY_ID = {
    entry.weapon_id: entry for entry in WEAPON_TABLE
}

WEAPON_PROJECTILE_TYPE_IDS: dict[int, tuple[int, ...]] = {
    # Source: analysis/ghidra/raw/crimsonland.exe_decompiled.c (`player_fire_weapon`).
    # Weapon ids not listed here use `type_id == weapon_id` in the native
    # `projectile_spawn` path.
    1: (0x01,),  # Pistol
    2: (0x02,),  # Assault Rifle
    3: (0x03,),  # Shotgun
    4: (0x03,),  # Sawed-off Shotgun
    5: (0x05,),  # Submachine Gun
    6: (0x06,),  # Gauss Gun
    7: (0x01,),  # Mean Minigun
    8: (),  # Flamethrower (particle path)
    9: (0x09,),  # Plasma Rifle
    10: (0x09, 0x0B),  # Multi-Plasma (spread includes 0x0B)
    11: (0x0B,),  # Plasma Minigun
    12: (),  # Rocket Launcher (secondary projectile pool)
    13: (),  # Seeker Rockets (secondary projectile pool)
    14: (0x0B,),  # Plasma Shotgun
    15: (),  # Blow Torch (particle path)
    16: (),  # HR Flamer (particle path)
    17: (),  # Mini-Rocket Swarmers (secondary projectile pool)
    18: (),  # Rocket Minigun (secondary projectile pool)
    19: (0x13,),  # Pulse Gun
    20: (0x03,),  # Jackhammer
    21: (0x15,),  # Ion Rifle
    22: (0x16,),  # Ion Minigun
    23: (0x17,),  # Ion Cannon
    24: (0x18,),  # Shrinkifier 5k
    25: (0x19,),  # Blade Gun
    28: (0x1C,),  # Plasma Cannon
    29: (0x1D,),  # Splitter Gun
    30: (0x06,),  # Gauss Shotgun
    31: (0x16,),  # Ion Shotgun
    41: (0x29,),  # Plague Spreader Gun
    42: (),  # Bubblegun (particle slow)
    43: (0x2B,),  # Rainbow Gun
    45: (0x2D,),  # Fire Bullets
}

def weapon_entry_for_projectile_type_id(type_id: int) -> Weapon | None:
    # Native `projectile_spawn` indexes the weapon table by `type_id`.
    return WEAPON_BY_ID.get(int(type_id))


def projectile_type_id_from_weapon_id(weapon_id: int) -> int | None:
    """Return the primary projectile `type_id` used by `weapon_id`.

    Returns `None` for weapons that don't use the main projectile pool.
    """

    weapon_id = int(weapon_id)
    type_ids = WEAPON_PROJECTILE_TYPE_IDS.get(weapon_id)
    if type_ids is not None:
        return int(type_ids[0]) if type_ids else None

    # Default native behavior for projectile weapons is `type_id == weapon_id`.
    if weapon_id in WEAPON_BY_ID:
        return weapon_id
    return None


def projectile_type_ids_from_weapon_id(weapon_id: int) -> tuple[int, ...]:
    """Return all projectile `type_id` values produced by `weapon_id`."""

    weapon_id = int(weapon_id)
    type_ids = WEAPON_PROJECTILE_TYPE_IDS.get(weapon_id)
    if type_ids is not None:
        return tuple(int(v) for v in type_ids)
    if weapon_id in WEAPON_BY_ID:
        return (weapon_id,)
    return ()


WEAPON_BY_NAME = {
    entry.name: entry for entry in WEAPON_TABLE if entry.name is not None
}
