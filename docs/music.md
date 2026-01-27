---
tags:
  - status-analysis
---

# Music (Game Tunes + First-Hit Trigger)

This note documents the original game's "iconic" Survival music behavior:
**menu music cuts on mode entry**, and a **random in-game tune starts on the first
projectile hit on a creature** (the impact SFX is suppressed for that hit).

## Game tune loading (playlist)

- `audio_init_music` (`0x0043c9c0`) loads core tracks and runs
  `exec music\\game_tunes.txt` during startup.

- `console_cmd_snd_add_game_tune` (`0x0042c360`) handles `snd_addGameTune` by
  loading `music\\<name>.ogg` and calling `music_queue_track` (`0x0043c960`),
  which appends the loaded track id into `music_playlist[]` and increments the
  count `DAT_004cc8d0`.

## "First hit starts the tune" gate

- `audio_init_music` defines a sentinel id `music_track_extra_0 =
  music_track_crimsonquest_id + 1`.

- `sfx_play_exclusive` (`0x0043d460`) treats `music_track_extra_0` specially:
  when called with the sentinel and the gate `DAT_004cc8d4 == 0`, it picks a
  random id from `music_playlist[]`, sets `DAT_004cc8d4 = 1`, and starts playback
  exclusively.

- `projectile_update` (`0x00420b90`) uses this gate: on the first creature
  impact (bullet/explosion path), if `demo_mode_active == 0`, `DAT_004cc8d4 == 0`
  and `game_mode != 2` (rush), it calls `sfx_play_exclusive(music_track_extra_0)`
  *instead of* playing the normal impact sound.

- `sfx_mute_all` (`0x0043d550`) resets the gate (`DAT_004cc8d4 = 0`), allowing
  the first-hit trigger to happen again next round.

## Menu -> gameplay transition

Mode entry paths mute menu music before entering gameplay. For example, the
victory screen handler `game_update_victory_screen` (`0x00406350`) mutes:
`music_track_crimson_theme_id`, `music_track_shortie_monk_id`, and
`music_track_extra_0` when starting Survival/Rush/Typ-o, immediately cutting the
menu theme and resetting the first-hit gate.

## Port behavior (this repo)

For Survival we mirror the original behavior:

- Entering Survival stops the menu theme.
- The first projectile hit starts a random queued game tune and suppresses the
  impact SFX for that hit.
- Leaving Survival stops the game tune; the menu theme resumes when the menu
  opens.
