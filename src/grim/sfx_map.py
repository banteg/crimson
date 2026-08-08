from __future__ import annotations

from enum import Enum
from typing import Final

import msgspec


class SfxId(Enum):
    TROOPER_INPAIN_01 = "sfx_trooper_inpain_01"
    TROOPER_INPAIN_02 = "sfx_trooper_inpain_02"
    TROOPER_INPAIN_03 = "sfx_trooper_inpain_03"
    TROOPER_DIE_01 = "sfx_trooper_die_01"
    TROOPER_DIE_02 = "sfx_trooper_die_02"
    TROOPER_DIE_03 = "sfx_trooper_die_03"
    ZOMBIE_DIE_01 = "sfx_zombie_die_01"
    ZOMBIE_DIE_02 = "sfx_zombie_die_02"
    ZOMBIE_DIE_03 = "sfx_zombie_die_03"
    ZOMBIE_DIE_04 = "sfx_zombie_die_04"
    ZOMBIE_ATTACK_01 = "sfx_zombie_attack_01"
    ZOMBIE_ATTACK_02 = "sfx_zombie_attack_02"
    ALIEN_DIE_01 = "sfx_alien_die_01"
    ALIEN_DIE_02 = "sfx_alien_die_02"
    ALIEN_DIE_03 = "sfx_alien_die_03"
    ALIEN_DIE_04 = "sfx_alien_die_04"
    ALIEN_ATTACK_01 = "sfx_alien_attack_01"
    ALIEN_ATTACK_02 = "sfx_alien_attack_02"
    LIZARD_DIE_01 = "sfx_lizard_die_01"
    LIZARD_DIE_02 = "sfx_lizard_die_02"
    LIZARD_DIE_03 = "sfx_lizard_die_03"
    LIZARD_DIE_04 = "sfx_lizard_die_04"
    LIZARD_ATTACK_01 = "sfx_lizard_attack_01"
    LIZARD_ATTACK_02 = "sfx_lizard_attack_02"
    SPIDER_DIE_01 = "sfx_spider_die_01"
    SPIDER_DIE_02 = "sfx_spider_die_02"
    SPIDER_DIE_03 = "sfx_spider_die_03"
    SPIDER_DIE_04 = "sfx_spider_die_04"
    SPIDER_ATTACK_01 = "sfx_spider_attack_01"
    SPIDER_ATTACK_02 = "sfx_spider_attack_02"
    PISTOL_FIRE = "sfx_pistol_fire"
    PISTOL_RELOAD = "sfx_pistol_reload"
    SHOTGUN_FIRE = "sfx_shotgun_fire"
    SHOTGUN_RELOAD = "sfx_shotgun_reload"
    AUTORIFLE_FIRE = "sfx_autorifle_fire"
    AUTORIFLE_RELOAD = "sfx_autorifle_reload"
    GAUSS_FIRE = "sfx_gauss_fire"
    HRPM_FIRE = "sfx_hrpm_fire"
    SHOCK_FIRE = "sfx_shock_fire"
    PLASMAMINIGUN_FIRE = "sfx_plasmaminigun_fire"
    PLASMASHOTGUN_FIRE = "sfx_plasmashotgun_fire"
    PULSE_FIRE = "sfx_pulse_fire"
    FLAMER_FIRE_01 = "sfx_flamer_fire_01"
    FLAMER_FIRE_02 = "sfx_flamer_fire_02"
    SHOCK_RELOAD = "sfx_shock_reload"
    SHOCK_FIRE_ALT = "sfx_shock_fire_alt"
    SHOCKMINIGUN_FIRE = "sfx_shockminigun_fire"
    ROCKET_FIRE = "sfx_rocket_fire"
    ROCKETMINI_FIRE = "sfx_rocketmini_fire"
    AUTORIFLE_RELOAD_ALT = "sfx_autorifle_reload_alt"
    BULLET_HIT_01 = "sfx_bullet_hit_01"
    BULLET_HIT_02 = "sfx_bullet_hit_02"
    BULLET_HIT_03 = "sfx_bullet_hit_03"
    BULLET_HIT_04 = "sfx_bullet_hit_04"
    BULLET_HIT_05 = "sfx_bullet_hit_05"
    BULLET_HIT_06 = "sfx_bullet_hit_06"
    SHOCK_HIT_01 = "sfx_shock_hit_01"
    EXPLOSION_SMALL = "sfx_explosion_small"
    EXPLOSION_MEDIUM = "sfx_explosion_medium"
    EXPLOSION_LARGE = "sfx_explosion_large"
    SHOCKWAVE = "sfx_shockwave"
    QUESTHIT = "sfx_questhit"
    UI_BONUS = "sfx_ui_bonus"
    UI_BUTTONCLICK = "sfx_ui_buttonclick"
    UI_PANELCLICK = "sfx_ui_panelclick"
    UI_LEVELUP = "sfx_ui_levelup"
    UI_TYPECLICK_01 = "sfx_ui_typeclick_01"
    UI_TYPECLICK_02 = "sfx_ui_typeclick_02"
    UI_TYPEENTER = "sfx_ui_typeenter"
    UI_CLINK_01 = "sfx_ui_clink_01"
    BLOODSPILL_01 = "sfx_bloodspill_01"
    BLOODSPILL_02 = "sfx_bloodspill_02"


class SfxSpec(msgspec.Struct, frozen=True):
    entry_name: str


_SFX_NATIVE_SPECS: Final[tuple[tuple[SfxId, SfxSpec], ...]] = (
    (SfxId.TROOPER_INPAIN_01, SfxSpec("trooper_inPain_01.ogg")),
    (SfxId.TROOPER_INPAIN_02, SfxSpec("trooper_inPain_02.ogg")),
    (SfxId.TROOPER_INPAIN_03, SfxSpec("trooper_inPain_03.ogg")),
    (SfxId.TROOPER_DIE_01, SfxSpec("trooper_die_01.ogg")),
    (SfxId.TROOPER_DIE_02, SfxSpec("trooper_die_02.ogg")),
    (SfxId.TROOPER_DIE_03, SfxSpec("trooper_die_03.ogg")),
    (SfxId.ZOMBIE_DIE_01, SfxSpec("zombie_die_01.ogg")),
    (SfxId.ZOMBIE_DIE_02, SfxSpec("zombie_die_02.ogg")),
    (SfxId.ZOMBIE_DIE_03, SfxSpec("zombie_die_03.ogg")),
    (SfxId.ZOMBIE_DIE_04, SfxSpec("zombie_die_04.ogg")),
    (SfxId.ZOMBIE_ATTACK_01, SfxSpec("zombie_attack_01.ogg")),
    (SfxId.ZOMBIE_ATTACK_02, SfxSpec("zombie_attack_02.ogg")),
    (SfxId.ALIEN_DIE_01, SfxSpec("alien_die_01.ogg")),
    (SfxId.ALIEN_DIE_02, SfxSpec("alien_die_02.ogg")),
    (SfxId.ALIEN_DIE_03, SfxSpec("alien_die_03.ogg")),
    (SfxId.ALIEN_DIE_04, SfxSpec("alien_die_04.ogg")),
    (SfxId.ALIEN_ATTACK_01, SfxSpec("alien_attack_01.ogg")),
    (SfxId.ALIEN_ATTACK_02, SfxSpec("alien_attack_02.ogg")),
    (SfxId.LIZARD_DIE_01, SfxSpec("lizard_die_01.ogg")),
    (SfxId.LIZARD_DIE_02, SfxSpec("lizard_die_02.ogg")),
    (SfxId.LIZARD_DIE_03, SfxSpec("lizard_die_03.ogg")),
    (SfxId.LIZARD_DIE_04, SfxSpec("lizard_die_04.ogg")),
    (SfxId.LIZARD_ATTACK_01, SfxSpec("lizard_attack_01.ogg")),
    (SfxId.LIZARD_ATTACK_02, SfxSpec("lizard_attack_02.ogg")),
    (SfxId.SPIDER_DIE_01, SfxSpec("spider_die_01.ogg")),
    (SfxId.SPIDER_DIE_02, SfxSpec("spider_die_02.ogg")),
    (SfxId.SPIDER_DIE_03, SfxSpec("spider_die_03.ogg")),
    (SfxId.SPIDER_DIE_04, SfxSpec("spider_die_04.ogg")),
    (SfxId.SPIDER_ATTACK_01, SfxSpec("spider_attack_01.ogg")),
    (SfxId.SPIDER_ATTACK_02, SfxSpec("spider_attack_02.ogg")),
    (SfxId.PISTOL_FIRE, SfxSpec("pistol_fire.ogg")),
    (SfxId.PISTOL_RELOAD, SfxSpec("pistol_reload.ogg")),
    (SfxId.SHOTGUN_FIRE, SfxSpec("shotgun_fire.ogg")),
    (SfxId.SHOTGUN_RELOAD, SfxSpec("shotgun_reload.ogg")),
    (SfxId.AUTORIFLE_FIRE, SfxSpec("autorifle_fire.ogg")),
    (SfxId.AUTORIFLE_RELOAD, SfxSpec("autorifle_reload.ogg")),
    (SfxId.GAUSS_FIRE, SfxSpec("gauss_fire.ogg")),
    (SfxId.HRPM_FIRE, SfxSpec("hrpm_fire.ogg")),
    (SfxId.SHOCK_FIRE, SfxSpec("shock_fire.ogg")),
    (SfxId.PLASMAMINIGUN_FIRE, SfxSpec("plasmaMinigun_fire.ogg")),
    (SfxId.PLASMASHOTGUN_FIRE, SfxSpec("plasmaShotgun_fire.ogg")),
    (SfxId.PULSE_FIRE, SfxSpec("pulse_fire.ogg")),
    (SfxId.FLAMER_FIRE_01, SfxSpec("flamer_fire_01.ogg")),
    (SfxId.FLAMER_FIRE_02, SfxSpec("flamer_fire_02.ogg")),
    (SfxId.SHOCK_RELOAD, SfxSpec("shock_reload.ogg")),
    (SfxId.SHOCK_FIRE_ALT, SfxSpec("shock_fire.ogg")),
    (SfxId.SHOCKMINIGUN_FIRE, SfxSpec("shockMinigun_fire.ogg")),
    (SfxId.ROCKET_FIRE, SfxSpec("rocket_fire.ogg")),
    (SfxId.ROCKETMINI_FIRE, SfxSpec("rocketmini_fire.ogg")),
    (SfxId.AUTORIFLE_RELOAD_ALT, SfxSpec("autorifle_reload.ogg")),
    (SfxId.BULLET_HIT_01, SfxSpec("bullet_hit_01.ogg")),
    (SfxId.BULLET_HIT_02, SfxSpec("bullet_hit_02.ogg")),
    (SfxId.BULLET_HIT_03, SfxSpec("bullet_hit_03.ogg")),
    (SfxId.BULLET_HIT_04, SfxSpec("bullet_hit_04.ogg")),
    (SfxId.BULLET_HIT_05, SfxSpec("bullet_hit_05.ogg")),
    (SfxId.BULLET_HIT_06, SfxSpec("bullet_hit_06.ogg")),
    (SfxId.SHOCK_HIT_01, SfxSpec("shock_hit_01.ogg")),
    (SfxId.EXPLOSION_SMALL, SfxSpec("explosion_small.ogg")),
    (SfxId.EXPLOSION_MEDIUM, SfxSpec("explosion_medium.ogg")),
    (SfxId.EXPLOSION_LARGE, SfxSpec("explosion_large.ogg")),
    (SfxId.SHOCKWAVE, SfxSpec("shockwave.ogg")),
    (SfxId.QUESTHIT, SfxSpec("questHit.ogg")),
    (SfxId.UI_BONUS, SfxSpec("ui_bonus.ogg")),
    (SfxId.UI_BUTTONCLICK, SfxSpec("ui_buttonClick.ogg")),
    (SfxId.UI_PANELCLICK, SfxSpec("ui_panelClick.ogg")),
    (SfxId.UI_LEVELUP, SfxSpec("ui_levelUp.ogg")),
    (SfxId.UI_TYPECLICK_01, SfxSpec("ui_typeClick_01.ogg")),
    (SfxId.UI_TYPECLICK_02, SfxSpec("ui_typeClick_02.ogg")),
    (SfxId.UI_TYPEENTER, SfxSpec("ui_typeEnter.ogg")),
    (SfxId.UI_CLINK_01, SfxSpec("ui_clink_01.ogg")),
    (SfxId.BLOODSPILL_01, SfxSpec("bloodSpill_01.ogg")),
    (SfxId.BLOODSPILL_02, SfxSpec("bloodSpill_02.ogg")),
)

SFX_SPECS: Final[dict[SfxId, SfxSpec]] = dict(_SFX_NATIVE_SPECS)

# Extracted from `audio_init_sfx` in `crimsonland.exe`.
# `sfx_load_sample()` allocates the first free slot, so the load order defines stable ids.
SFX_NATIVE_ORDER: Final[tuple[SfxId, ...]] = tuple(sfx_id for sfx_id, _spec in _SFX_NATIVE_SPECS)
