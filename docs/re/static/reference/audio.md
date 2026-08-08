---
tags:
  - status-analysis
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

- `sfx_voice_table` (`0x004c3e80`) is a 0x20-entry table of DirectSound buffer
  pointers; it is only zeroed during `sfx_system_init`, so the role remains
  inferred.

## Memory-backed Vorbis stream

The native `vorbis_stream_t` is now recovered through its complete leaf
surface. Its leading layout is an `ov_callbacks` record at `+0x00`, an
`OggVorbis_File` at `+0x10`, the current bitstream index at `+0x2e0`, total PCM
bytes at `+0x2e4`, source-data offset at `+0x2e8`, the owned source allocation
at `+0x2ec`, and a copied 32-byte `vorbis_info` at `+0x2f0`.

The owned allocation has an eight-byte prefix followed by inline OGG data:

| Offset | Type | Meaning |
| --- | --- | --- |
| 0x00 | u32 | Source byte size. |
| 0x04 | long | Callback cursor. |
| 0x08 | u8[] | OGG bytes passed to `ov_open_callbacks`. |

The callback policy contains several native quirks that ports should retain:

- reads reset an exhausted cursor to zero, clamp the copy to remaining bytes,
  but advance the cursor by the full requested `size * count`;
- seek returns `1` for every origin, treats non-`SEEK_SET`/`SEEK_END` origins
  as relative, and implements end-relative seek as `size - offset`;
- the callback close is a no-op returning `1`; `vorbis_stream_t::close` owns
  the allocation and frees it before `ov_clear`;
- PCM reads request signed little-endian 16-bit output and clamp negative
  `ov_read` results to zero.

Opening copies `vorbis_info`, calculates PCM bytes as
`ov_pcm_total * channels * 16 / 8`, and records the callback cursor after the
Vorbis headers have been consumed.

## SFX ID map

Derived from `audio_init_sfx` (`0x0043caa0`). `sfx_load_sample` (`0x0043c740`)
returns the SFX id for each `.ogg` file and stores it in a global variable.

Labels are mirrored into `analysis/ghidra/maps/data_map.json` and applied with
`ApplyDataMap.java` during headless analysis. Duplicate IDs that point at the
same `.ogg` file use `_alt` suffixes to keep names unique.

| Var | File | Label | Refs |
| --- | --- | --- | --- |
| 0x004c3f00 | trooper_inPain_01.ogg | sfx_trooper_inpain_01 | 6 |
| 0x004c3f04 | trooper_inPain_02.ogg | sfx_trooper_inpain_02 | |
| 0x004c3f08 | trooper_inPain_03.ogg | sfx_trooper_inpain_03 | |
| 0x004c3f0c | trooper_die_01.ogg | sfx_trooper_die_01 | 3 |
| 0x004c3f10 | trooper_die_02.ogg | sfx_trooper_die_02 | |
| 0x004c3f14 | trooper_die_03.ogg | sfx_trooper_die_03 | |
| 0x004c3f18 | zombie_die_01.ogg | sfx_zombie_die_01 | |
| 0x004c3f1c | zombie_die_02.ogg | sfx_zombie_die_02 | |
| 0x004c3f20 | zombie_die_03.ogg | sfx_zombie_die_03 | |
| 0x004c3f24 | zombie_die_04.ogg | sfx_zombie_die_04 | |
| 0x004c3f28 | zombie_attack_01.ogg | sfx_zombie_attack_01 | |
| 0x004c3f2c | zombie_attack_02.ogg | sfx_zombie_attack_02 | |
| 0x004c3f30 | alien_die_01.ogg | sfx_alien_die_01 | |
| 0x004c3f34 | alien_die_02.ogg | sfx_alien_die_02 | |
| 0x004c3f38 | alien_die_03.ogg | sfx_alien_die_03 | |
| 0x004c3f3c | alien_die_04.ogg | sfx_alien_die_04 | |
| 0x004c3f40 | alien_attack_01.ogg | sfx_alien_attack_01 | |
| 0x004c3f44 | alien_attack_02.ogg | sfx_alien_attack_02 | |
| 0x004c3f48 | lizard_die_01.ogg | sfx_lizard_die_01 | |
| 0x004c3f4c | lizard_die_02.ogg | sfx_lizard_die_02 | |
| 0x004c3f50 | lizard_die_03.ogg | sfx_lizard_die_03 | |
| 0x004c3f54 | lizard_die_04.ogg | sfx_lizard_die_04 | |
| 0x004c3f58 | lizard_attack_01.ogg | sfx_lizard_attack_01 | |
| 0x004c3f5c | lizard_attack_02.ogg | sfx_lizard_attack_02 | |
| 0x004c3f60 | spider_die_01.ogg | sfx_spider_die_01 | 3 |
| 0x004c3f64 | spider_die_02.ogg | sfx_spider_die_02 | 3 |
| 0x004c3f68 | spider_die_03.ogg | sfx_spider_die_03 | 3 |
| 0x004c3f6c | spider_die_04.ogg | sfx_spider_die_04 | 3 |
| 0x004c3f70 | spider_attack_01.ogg | sfx_spider_attack_01 | 3 |
| 0x004c3f74 | spider_attack_02.ogg | sfx_spider_attack_02 | 3 |
| 0x004c3f78 | pistol_fire.ogg | sfx_pistol_fire | |
| 0x004c3f7c | pistol_reload.ogg | sfx_pistol_reload | 3 |
| 0x004c3f80 | shotgun_fire.ogg | sfx_shotgun_fire | 3 |
| 0x004c3f84 | shotgun_reload.ogg | sfx_shotgun_reload | |
| 0x004c3f88 | autorifle_fire.ogg | sfx_autorifle_fire | 3 |
| 0x004c3f8c | autorifle_reload.ogg | sfx_autorifle_reload | 3 |
| 0x004c3f90 | gauss_fire.ogg | sfx_gauss_fire | 3 |
| 0x004c3f98 | hrpm_fire.ogg | sfx_hrpm_fire | |
| 0x004c3f9c | shock_fire.ogg | sfx_shock_fire | 6 |
| 0x004c3fa0 | plasmaMinigun_fire.ogg | sfx_plasmaminigun_fire | 3 |
| 0x004c3fa4 | plasmaShotgun_fire.ogg | sfx_plasmashotgun_fire | 2 |
| 0x004c3fa8 | pulse_fire.ogg | sfx_pulse_fire | 2 |
| 0x004c3fac | flamer_fire_01.ogg | sfx_flamer_fire_01 | 7 |
| 0x004c3fb0 | flamer_fire_02.ogg | sfx_flamer_fire_02 | 3 |
| 0x004c3fb4 | shock_fire.ogg | sfx_shock_fire_alt | 9 |
| 0x004c3fb8 | shockMinigun_fire.ogg | sfx_shockminigun_fire | 2 |
| 0x004c3fbc | shock_reload.ogg | sfx_shock_reload | 2 |
| 0x004c3fc0 | rocket_fire.ogg | sfx_rocket_fire | 4 |
| 0x004c3fc4 | rocketmini_fire.ogg | sfx_rocketmini_fire | 2 |
| 0x004c3fc8 | autorifle_reload.ogg | sfx_autorifle_reload_alt | 5 |
| 0x004c3fcc | bullet_hit_01.ogg | sfx_bullet_hit_01 | 2 |
| 0x004c3fd0 | bullet_hit_02.ogg | sfx_bullet_hit_02 | |
| 0x004c3fd4 | bullet_hit_03.ogg | sfx_bullet_hit_03 | |
| 0x004c3fd8 | bullet_hit_04.ogg | sfx_bullet_hit_04 | |
| 0x004c3fdc | bullet_hit_05.ogg | sfx_bullet_hit_05 | |
| 0x004c3fe0 | bullet_hit_06.ogg | sfx_bullet_hit_06 | |
| 0x004c3fe4 | shock_hit_01.ogg | sfx_shock_hit_01 | 5 |
| 0x004c3fe8 | explosion_small.ogg | sfx_explosion_small | |
| 0x004c3fec | explosion_medium.ogg | sfx_explosion_medium | 4 |
| 0x004c3ff0 | explosion_large.ogg | sfx_explosion_large | 4 |
| 0x004c3ff4 | shockwave.ogg | sfx_shockwave | 6 |
| 0x004c3ff8 | questHit.ogg | sfx_questhit | 2 |
| 0x004c3ffc | ui_bonus.ogg | sfx_ui_bonus | 4 |
| 0x004c400c | ui_buttonClick.ogg | sfx_ui_buttonclick | 5 |
| 0x004c4010 | ui_panelClick.ogg | sfx_ui_panelclick | 2 |
| 0x004c4014 | ui_levelUp.ogg | sfx_ui_levelup | 2 |
| 0x004c4018 | ui_typeClick_01.ogg | sfx_ui_typeclick_01 | 4 |
| 0x004c401c | ui_typeClick_02.ogg | sfx_ui_typeclick_02 | |
| 0x004c4020 | ui_typeEnter.ogg | sfx_ui_typeenter | 5 |
| 0x004c4024 | ui_clink_01.ogg | sfx_ui_clink_01 | 4 |
| 0x004c4028 | bloodSpill_01.ogg | sfx_bloodspill_01 | 3 |
| 0x004c402c | bloodSpill_02.ogg | sfx_bloodspill_02 | |

## Aliases

Alias entries are direct copies of another id in the init function.

| Var | Copies | Label |
| --- | --- | --- |
| 0x004c4000 | sfx_trooper_inpain_01 | sfx_trooper_inpain_01_alias_0 |
| sfx_jinxed_kill | sfx_trooper_inpain_01 | sfx_trooper_inpain_01_alias_1 |
| 0x004c4008 | sfx_trooper_inpain_01 | sfx_trooper_inpain_01_alias_2 |

## Playlist/runtime globals

Recovered data labels for exclusive music-play path:

- `music_playlist_entry_count` (`0x004cc8d0`): number of queued entries in
  `music_playlist` (written by `music_queue_track`).
- `music_playlist_randomized_latch` (`0x004cc8d4`): latch used by
  `sfx_play_exclusive(music_track_extra_0)` to avoid re-randomizing every call.
- `audio_assets_loaded_count` (`0x004cc8d8`): increments on
  `sfx_load_sample`/`music_load_track`; displayed on startup loading UI
  (`"Grim SFX: %d/%d"` line).

## Runtime callsite clusters (2026-02-06 capture)

From `analysis/frida/gameplay_state_capture_summary.json` (694s gameplay-heavy run):

- `quest_results_screen_update` -> `sfx_play_exclusive(5)` in 3989/3989 calls.
- `game_over_screen_update` -> `sfx_play_exclusive(1)` in 714/716 calls.
- `quest_failed_screen_update` -> `sfx_play_exclusive(1)` in 482/483 calls.
- `ui_button_update` -> `sfx_play(63)` in 38/38 calls.
- `ui_element_update` -> mostly `sfx_play(64)` (95/108) with secondary `63` (13/108).

Gameplay-heavy panned clusters (same capture):

- `player_update`: dominant IDs `34` and `37` (plus `30`), matching weapon-fire cadence.
- `projectile_update`: dominant IDs `54/51/53/55/52/50` (projectile hit/explosion family).
- `player_take_damage`: IDs `0/2/1` (player hurt variants).
- `player_start_reload`: mostly ID `35` (15/20).
- `bonus_apply`: dominant `sfx_play` ID `62`; panned side effects include `56/59/60`.
- `weapon_assign_player`: panned cluster led by `31` with secondary `35/49`.

## Unreferenced entries (in sfx.paq)

These files exist in `sfx.paq`, but are not loaded by `audio_init_sfx` in 1.9.93:

- `flamer_fire_start.ogg`
- `trooper_die_04.ogg`
- `trooper_inPain_04.ogg`
