from __future__ import annotations

from typing import Final

# Extracted from `audio_init_sfx` (FUN_0043caa0) in `crimsonland.exe`.
# `sfx_load_sample()` allocates the first free slot, so the load order defines stable ids.

SFX_LOAD_ORDER: Final[tuple[tuple[str, str], ...]] = (
    ("sfx_trooper_inpain_01", "trooper_inPain_01.ogg"),
    ("sfx_trooper_inpain_02", "trooper_inPain_02.ogg"),
    ("sfx_trooper_inpain_03", "trooper_inPain_03.ogg"),
    ("sfx_trooper_die_01", "trooper_die_01.ogg"),
    ("sfx_trooper_die_02", "trooper_die_02.ogg"),
    ("sfx_trooper_die_03", "trooper_die_03.ogg"),
    ("sfx_zombie_die_01", "zombie_die_01.ogg"),
    ("sfx_zombie_die_02", "zombie_die_02.ogg"),
    ("sfx_zombie_die_03", "zombie_die_03.ogg"),
    ("sfx_zombie_die_04", "zombie_die_04.ogg"),
    ("sfx_zombie_attack_01", "zombie_attack_01.ogg"),
    ("sfx_zombie_attack_02", "zombie_attack_02.ogg"),
    ("sfx_alien_die_01", "alien_die_01.ogg"),
    ("sfx_alien_die_02", "alien_die_02.ogg"),
    ("sfx_alien_die_03", "alien_die_03.ogg"),
    ("sfx_alien_die_04", "alien_die_04.ogg"),
    ("sfx_alien_attack_01", "alien_attack_01.ogg"),
    ("sfx_alien_attack_02", "alien_attack_02.ogg"),
    ("sfx_lizard_die_01", "lizard_die_01.ogg"),
    ("sfx_lizard_die_02", "lizard_die_02.ogg"),
    ("sfx_lizard_die_03", "lizard_die_03.ogg"),
    ("sfx_lizard_die_04", "lizard_die_04.ogg"),
    ("sfx_lizard_attack_01", "lizard_attack_01.ogg"),
    ("sfx_lizard_attack_02", "lizard_attack_02.ogg"),
    ("sfx_spider_die_01", "spider_die_01.ogg"),
    ("sfx_spider_die_02", "spider_die_02.ogg"),
    ("sfx_spider_die_03", "spider_die_03.ogg"),
    ("sfx_spider_die_04", "spider_die_04.ogg"),
    ("sfx_spider_attack_01", "spider_attack_01.ogg"),
    ("sfx_spider_attack_02", "spider_attack_02.ogg"),
    ("sfx_pistol_fire", "pistol_fire.ogg"),
    ("sfx_pistol_reload", "pistol_reload.ogg"),
    ("sfx_shotgun_fire", "shotgun_fire.ogg"),
    ("sfx_shotgun_reload", "shotgun_reload.ogg"),
    ("sfx_autorifle_fire", "autorifle_fire.ogg"),
    ("sfx_autorifle_reload", "autorifle_reload.ogg"),
    ("sfx_gauss_fire", "gauss_fire.ogg"),
    ("sfx_hrpm_fire", "hrpm_fire.ogg"),
    ("sfx_shock_fire", "shock_fire.ogg"),
    ("sfx_plasmaminigun_fire", "plasmaMinigun_fire.ogg"),
    ("sfx_plasmashotgun_fire", "plasmaShotgun_fire.ogg"),
    ("sfx_pulse_fire", "pulse_fire.ogg"),
    ("sfx_flamer_fire_01", "flamer_fire_01.ogg"),
    ("sfx_flamer_fire_02", "flamer_fire_02.ogg"),
    ("sfx_shock_reload", "shock_reload.ogg"),
    ("sfx_shock_fire_alt", "shock_fire.ogg"),
    ("sfx_shockminigun_fire", "shockMinigun_fire.ogg"),
    ("sfx_rocket_fire", "rocket_fire.ogg"),
    ("sfx_rocketmini_fire", "rocketmini_fire.ogg"),
    ("sfx_autorifle_reload_alt", "autorifle_reload.ogg"),
    ("sfx_bullet_hit_01", "bullet_hit_01.ogg"),
    ("sfx_bullet_hit_02", "bullet_hit_02.ogg"),
    ("sfx_bullet_hit_03", "bullet_hit_03.ogg"),
    ("sfx_bullet_hit_04", "bullet_hit_04.ogg"),
    ("sfx_bullet_hit_05", "bullet_hit_05.ogg"),
    ("sfx_bullet_hit_06", "bullet_hit_06.ogg"),
    ("sfx_shock_hit_01", "shock_hit_01.ogg"),
    ("sfx_explosion_small", "explosion_small.ogg"),
    ("sfx_explosion_medium", "explosion_medium.ogg"),
    ("sfx_explosion_large", "explosion_large.ogg"),
    ("sfx_shockwave", "shockwave.ogg"),
    ("sfx_questhit", "questHit.ogg"),
    ("sfx_ui_bonus", "ui_bonus.ogg"),
    ("sfx_ui_buttonclick", "ui_buttonClick.ogg"),
    ("sfx_ui_panelclick", "ui_panelClick.ogg"),
    ("sfx_ui_levelup", "ui_levelUp.ogg"),
    ("sfx_ui_typeclick_01", "ui_typeClick_01.ogg"),
    ("sfx_ui_typeclick_02", "ui_typeClick_02.ogg"),
    ("sfx_ui_typeenter", "ui_typeEnter.ogg"),
    ("sfx_ui_clink_01", "ui_clink_01.ogg"),
    ("sfx_bloodspill_01", "bloodSpill_01.ogg"),
    ("sfx_bloodspill_02", "bloodSpill_02.ogg"),
)

SFX_KEY_ALIASES: Final[dict[str, str]] = {
    "sfx_trooper_inpain_01_alias_0": "sfx_trooper_inpain_01",
    "sfx_trooper_inpain_01_alias_1": "sfx_trooper_inpain_01",
    "sfx_trooper_inpain_01_alias_2": "sfx_trooper_inpain_01",
}

# Present in `sfx.paq`, but not loaded by `audio_init_sfx` in 1.9.93 (unused or runtime-loaded).
SFX_UNREFERENCED: Final[tuple[tuple[str, str], ...]] = (
    ("sfx_trooper_inpain_04", "trooper_inPain_04.ogg"),
    ("sfx_trooper_die_04", "trooper_die_04.ogg"),
    ("sfx_flamer_fire_start", "flamer_fire_start.ogg"),
)

SFX_KEY_BY_ID: Final[tuple[str, ...]] = tuple(key for key, _entry in SFX_LOAD_ORDER)
SFX_ID_BY_KEY: Final[dict[str, int]] = {key: idx for idx, (key, _entry) in enumerate(SFX_LOAD_ORDER)}

SFX_ENTRY_BY_KEY: Final[dict[str, str]] = {
    **{key: entry for key, entry in SFX_LOAD_ORDER},
    **{key: entry for key, entry in SFX_UNREFERENCED},
}

