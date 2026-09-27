---
tags:
  - rewrite
  - parity
---

# Settings that steer the RNG

The original game has one gameplay RNG (`crt_rand`). Spawns, drops and AI draw
from it, but so do presentation paths: hit sounds, the music playlist, blood and
particles. Anything that gates one of those presentation paths changes which draws
happen, and from then on every spawn and drop. Machine state and options can
therefore change how a run plays out.

We found this when a Windows machine lost its audio device. The original game
failed to start music, and its RNG stream stopped matching the port's.

Policy for the port and ranked play: every such input is either fixed in place,
with the sim assuming the canonical value and never reading the real one, or
recorded in the replay and pinned for ranked runs. Add newly found gates here.

| Gate | Original behavior | Port | Original captures |
|---|---|---|---|
| Audio | see [Audio](#audio) | fixed: assumes audio works | rejected when closed |
| Game tune latch | global, cleared by every other track | per-run flag, clear at run start | checked clear at run start |
| Detail preset (1..5) | effect spawns draw per preset | recorded in `RunSpec.detail_preset` | recorded |
| Violence disabled | blood and particle paths draw or skip | recorded in `RunSpec.violence_disabled` | recorded |
| Attract mode | `demo_mode_active` skips the game tune | removed: runs are never attract mode | not captured |

## Audio

The first eligible bullet or secondary-projectile hit of a run
(`projectile_update`, not in Rush) calls `sfx_play_exclusive(music_track_extra_0)`
instead of playing its hit sound while `music_playlist_randomized_latch` is clear.
`sfx_play_exclusive` returns early unless all of the following hold:

- audio initialized (`sfx_unmuted_flag`, set by `audio_init_music`)
- sound and music are enabled in the config
- the playlist is not empty (`music\game_tunes.txt` queued tracks)
- no plugin runtime is active

Only then does it draw `crt_rand() % music_playlist_entry_count` and set the latch.
With the gate open, a run draws once for the playlist, then one hit-sound rand per
later hit. With the gate closed the latch never sets, so every hit takes the tune
branch and draws nothing.

The port always takes the open-gate path (`plan_hit_sfx` and
`WorldState` hit audio, `DeterministicSession.game_tune_started`). Its sound and
music options only mute output. Recorded runs, and their verification, do not
depend on the player's audio device or settings.

## Game tune latch

The latch is global, not per run. Any other `sfx_play_exclusive` call clears it
(with the audio gate open), and every route into a run passes one: startup, pause
to main menu, game over, quest results and quest failed. So it is clear at every
run start, which the port's per-session flag models. The one unmodeled clear is the
quest completion music at 2000 ms into the completion transition. No hit can land
then, because no creatures are left.

## Detail and violence

Both are recorded run inputs, so replays verify under any value. Ranked runs with
different values still play out differently. The ranked profile calls for full
detail, but nothing enforces it yet. Pinning both for ranked runs would treat them
like audio.

## Original captures

`scripts/frida/gameplay_diff_capture.js` rejects a run at start with
`audio_rng_gate_closed:<reason>` when the audio gate is closed or the tune latch
is set. The port cannot reproduce such a stream.
