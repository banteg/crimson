---
tags:
  - status-tracking
---

# Audio

This page documents the audio system: SFX IDs, usage hotspots, data labels, and
the runtime entry struct shared by SFX and music.

## Entry struct (audio_entry_t)

SFX and music tracks share the same 0x84-byte entry layout. The runtime uses
this struct for both `sfx_entry_table` and `music_entry_table`.

Offsets are relative to the entry base and match the initialization logic in
`wav_parse_into_entry`, `sfx_entry_load_ogg`, and `music_entry_load_ogg`.

| Offset | Size | Field | Notes |
| --- | --- | --- | --- |
| 0x00 | u16 | format_tag | Set to `1` (PCM) for WAV and OGG decode. |
| 0x02 | u16 | channels | Written from WAV header / Vorbis info. |
| 0x04 | u32 | sample_rate | `nSamplesPerSec`. |
| 0x08 | u32 | avg_bytes_per_sec | `nAvgBytesPerSec`. |
| 0x0c | u16 | block_align | `nBlockAlign`. |
| 0x0e | u16 | bits_per_sample | `wBitsPerSample` (usually 16). |
| 0x10 | u16 | cb_size | Extra size (usually 0). |
| 0x12 | u16 | _pad | Alignment. |
| 0x14 | ptr | pcm_data | Heap buffer holding decoded PCM. |
| 0x18 | u32 | pcm_bytes | Size of `pcm_data` / stream buffer in bytes. |
| 0x1c | u32 | stream_cursor | Current cursor used by streaming refill logic. |
| 0x20 | f32 | volume | Cached volume scalar. |
| 0x24 | ptr[16] | buffers | DirectSound buffer pointers (primary + 15 duplicates). |
| 0x64 | u8[16] | buffer_in_use | Voice-active flags set during playback. |
| 0x74 | ptr | vorbis_stream | Non-null for streaming music entries. |
| 0x78 | u32 | stream_fill_bytes | Bytes remaining in the current stream chunk. |
| 0x7c | u32 | stream_total_bytes | Accumulated bytes written to the stream. |
| 0x80 | u32 | stream_cursor_bytes | Cursor used to trigger refill in `music_stream_update`. |

Notes:

- Static/one-shot SFX entries leave `vorbis_stream` null and use the 16 voice
  buffers at `0x24` for overlapping playback.
- Music tracks set `vorbis_stream` and use a single streaming buffer at `0x24`.
- The entry size is 0x84 bytes; table strides for `sfx_entry_table` and
  `music_entry_table` use this size.

## SFX ID map

Derived from `audio_init_sfx` (`FUN_0043caa0`). `sfx_load_sample` (`FUN_0043c740`)
returns the SFX id for each `.ogg` file and stores it in a global variable.

Labels are mirrored into `analysis/ghidra/maps/data_map.json` and applied with
`ApplyDataMap.java` during headless analysis. Duplicate IDs that point at the
same `.ogg` file use `_alt` suffixes to keep names unique.

| Var | File | Label | Refs |
| --- | --- | --- | --- |
| DAT_004c3f00 | trooper_inPain_01.ogg | sfx_trooper_inpain_01 | 6 |
| DAT_004c3f04 | trooper_inPain_02.ogg | sfx_trooper_inpain_02 | |
| _DAT_004c3f08 | trooper_inPain_03.ogg | sfx_trooper_inpain_03 | |
| DAT_004c3f0c | trooper_die_01.ogg | sfx_trooper_die_01 | 3 |
| DAT_004c3f10 | trooper_die_02.ogg | sfx_trooper_die_02 | |
| DAT_004c3f14 | trooper_die_03.ogg | sfx_trooper_die_03 | |
| DAT_004c3f18 | zombie_die_01.ogg | sfx_zombie_die_01 | |
| DAT_004c3f1c | zombie_die_02.ogg | sfx_zombie_die_02 | |
| DAT_004c3f20 | zombie_die_03.ogg | sfx_zombie_die_03 | |
| DAT_004c3f24 | zombie_die_04.ogg | sfx_zombie_die_04 | |
| DAT_004c3f28 | zombie_attack_01.ogg | sfx_zombie_attack_01 | |
| DAT_004c3f2c | zombie_attack_02.ogg | sfx_zombie_attack_02 | |
| DAT_004c3f30 | alien_die_01.ogg | sfx_alien_die_01 | |
| DAT_004c3f34 | alien_die_02.ogg | sfx_alien_die_02 | |
| DAT_004c3f38 | alien_die_03.ogg | sfx_alien_die_03 | |
| DAT_004c3f3c | alien_die_04.ogg | sfx_alien_die_04 | |
| DAT_004c3f40 | alien_attack_01.ogg | sfx_alien_attack_01 | |
| DAT_004c3f44 | alien_attack_02.ogg | sfx_alien_attack_02 | |
| DAT_004c3f48 | lizard_die_01.ogg | sfx_lizard_die_01 | |
| DAT_004c3f4c | lizard_die_02.ogg | sfx_lizard_die_02 | |
| DAT_004c3f50 | lizard_die_03.ogg | sfx_lizard_die_03 | |
| DAT_004c3f54 | lizard_die_04.ogg | sfx_lizard_die_04 | |
| DAT_004c3f58 | lizard_attack_01.ogg | sfx_lizard_attack_01 | |
| DAT_004c3f5c | lizard_attack_02.ogg | sfx_lizard_attack_02 | |
| DAT_004c3f60 | spider_die_01.ogg | sfx_spider_die_01 | 3 |
| DAT_004c3f64 | spider_die_02.ogg | sfx_spider_die_02 | 3 |
| DAT_004c3f68 | spider_die_03.ogg | sfx_spider_die_03 | 3 |
| DAT_004c3f6c | spider_die_04.ogg | sfx_spider_die_04 | 3 |
| DAT_004c3f70 | spider_attack_01.ogg | sfx_spider_attack_01 | 3 |
| DAT_004c3f74 | spider_attack_02.ogg | sfx_spider_attack_02 | 3 |
| DAT_004c3f78 | pistol_fire.ogg | sfx_pistol_fire | |
| DAT_004c3f7c | pistol_reload.ogg | sfx_pistol_reload | 3 |
| DAT_004c3f80 | shotgun_fire.ogg | sfx_shotgun_fire | 3 |
| DAT_004c3f84 | shotgun_reload.ogg | sfx_shotgun_reload | |
| DAT_004c3f88 | autorifle_fire.ogg | sfx_autorifle_fire | 3 |
| DAT_004c3f8c | autorifle_reload.ogg | sfx_autorifle_reload | 3 |
| DAT_004c3f90 | gauss_fire.ogg | sfx_gauss_fire | 3 |
| DAT_004c3f98 | hrpm_fire.ogg | sfx_hrpm_fire | |
| DAT_004c3f9c | shock_fire.ogg | sfx_shock_fire | 6 |
| DAT_004c3fa0 | plasmaMinigun_fire.ogg | sfx_plasmaminigun_fire | 3 |
| DAT_004c3fa4 | plasmaShotgun_fire.ogg | sfx_plasmashotgun_fire | 2 |
| DAT_004c3fa8 | pulse_fire.ogg | sfx_pulse_fire | 2 |
| DAT_004c3fac | flamer_fire_01.ogg | sfx_flamer_fire_01 | 7 |
| DAT_004c3fb0 | flamer_fire_02.ogg | sfx_flamer_fire_02 | 3 |
| DAT_004c3fb4 | shock_fire.ogg | sfx_shock_fire_alt | 9 |
| DAT_004c3fb8 | shockMinigun_fire.ogg | sfx_shockminigun_fire | 2 |
| DAT_004c3fbc | shock_reload.ogg | sfx_shock_reload | 2 |
| DAT_004c3fc0 | rocket_fire.ogg | sfx_rocket_fire | 4 |
| DAT_004c3fc4 | rocketmini_fire.ogg | sfx_rocketmini_fire | 2 |
| DAT_004c3fc8 | autorifle_reload.ogg | sfx_autorifle_reload_alt | 5 |
| DAT_004c3fcc | bullet_hit_01.ogg | sfx_bullet_hit_01 | 2 |
| _DAT_004c3fd0 | bullet_hit_02.ogg | sfx_bullet_hit_02 | |
| _DAT_004c3fd4 | bullet_hit_03.ogg | sfx_bullet_hit_03 | |
| _DAT_004c3fd8 | bullet_hit_04.ogg | sfx_bullet_hit_04 | |
| _DAT_004c3fdc | bullet_hit_05.ogg | sfx_bullet_hit_05 | |
| _DAT_004c3fe0 | bullet_hit_06.ogg | sfx_bullet_hit_06 | |
| DAT_004c3fe4 | shock_hit_01.ogg | sfx_shock_hit_01 | 5 |
| DAT_004c3fe8 | explosion_small.ogg | sfx_explosion_small | |
| DAT_004c3fec | explosion_medium.ogg | sfx_explosion_medium | 4 |
| DAT_004c3ff0 | explosion_large.ogg | sfx_explosion_large | 4 |
| DAT_004c3ff4 | shockwave.ogg | sfx_shockwave | 6 |
| DAT_004c3ff8 | questHit.ogg | sfx_questhit | 2 |
| DAT_004c3ffc | ui_bonus.ogg | sfx_ui_bonus | 4 |
| DAT_004c400c | ui_buttonClick.ogg | sfx_ui_buttonclick | 5 |
| DAT_004c4010 | ui_panelClick.ogg | sfx_ui_panelclick | 2 |
| DAT_004c4014 | ui_levelUp.ogg | sfx_ui_levelup | 2 |
| _DAT_004c4018 | ui_typeClick_01.ogg | sfx_ui_typeclick_01 | 4 |
| _DAT_004c401c | ui_typeClick_02.ogg | sfx_ui_typeclick_02 | |
| DAT_004c4020 | ui_typeEnter.ogg | sfx_ui_typeenter | 5 |
| DAT_004c4024 | ui_clink_01.ogg | sfx_ui_clink_01 | 4 |
| DAT_004c4028 | bloodSpill_01.ogg | sfx_bloodspill_01 | 3 |
| _DAT_004c402c | bloodSpill_02.ogg | sfx_bloodspill_02 | |

## Aliases

Alias entries are direct copies of another id in the init function.

| Var | Copies | Label |
| --- | --- | --- |
| _DAT_004c4000 | DAT_004c3f00 | sfx_trooper_inpain_01_alias_0 |
| DAT_004c4004 | DAT_004c3f00 | sfx_trooper_inpain_01_alias_1 |
| _DAT_004c4008 | DAT_004c3f00 | sfx_trooper_inpain_01_alias_2 |
