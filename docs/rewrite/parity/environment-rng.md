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

| Gate | Original behavior | Port |
|---|---|---|
| Audio | see [Audio](#audio) | fixed: assumes audio works |
| Game tune latch | global, cleared by every other track | per-run flag, clear at run start |
| Detail preset (1..5) | effect spawns draw per preset | recorded; ranked runs need 5 |
| Violence disabled | blood and particle paths draw or skip | recorded; ranked runs need violence on |
| Attract mode | `demo_mode_active` skips the game tune | removed: runs are never attract mode |
| Frames outside gameplay | one discarded draw per frame | fixed: none |
| Corpse fading (`cv_bodiesFade`) | off frees a corpse's slot the frame it dies | fixed: corpses fade |
| Weapon history | a used weapon costs an extra draw in the drop reroll | recorded; ranked runs start with none |
| Quest retries | each failure softens the next attempt's creatures | recorded; ranked runs play as the first try |
| Seed | the session RNG carries into the next run | recorded; ranked runs draw a fresh seed |
| Screen size and pad reach | the cursor is clamped to the screen; pad reach follows `cv_padAimDistMul` | the aim is recorded; ranked runs bound it to a 1024x768 view and the default reach |

## Audio

The first eligible bullet or secondary-projectile hit of a run
(`projectile_update`, not in Rush) calls `music_play_exclusive(music_track_game_playlist)`
instead of playing its hit sound while `music_playlist_randomized_latch` is clear.
`music_play_exclusive` returns early unless all of the following hold:

- audio initialized (`music_ready`, set by `audio_init_music`)
- sound and music are enabled in the config
- the playlist is not empty (`music\game_tunes.txt` queued tracks)
- no plugin runtime is active

Only then does it draw `crt_rand() % music_playlist_entry_count` and set the latch.
With the gate open, a run draws once for the playlist, then one hit-sound rand per
later hit. With the gate closed the latch never sets, so every hit takes the tune
branch and draws nothing.

The port always takes the open-gate path (`plan_hit_sfx` and
`WorldState` hit audio, `GameplayState.game_tune_started`). Its sound and
music options only mute output. Recorded runs, and their verification, do not
depend on the player's audio device or settings.

## Game tune latch

The latch is global, not per run. Any other `music_play_exclusive` call clears it
(with the audio gate open), and every route into a run passes one: startup, pause
to main menu, game over, quest results and quest failed. So it is clear at every
run start, which the port's per-session flag models. The one unmodeled clear is the
quest completion music at 2000 ms into the completion transition. No hit can land
then, because no creatures are left.

## Detail and violence

Both are recorded run inputs, so replays verify under any value and a run at low
detail plays exactly as the original does at low detail. The leaderboard ranks
only runs in the [ranked profile](../ranked-rules.md), which pins these and the
other recorded gates above; runs outside it still verify, they just do not rank.

## Frames outside gameplay

`game_frame_update` ends every frame with a discarded `crt_rand()`, whatever the
state. Each port tick carries its gameplay frame's draw. Pause, the perk menu and
the menu's slide-in and slide-out frames draw too, and their count depends on
wall-clock time and frame rate, so waiting in a menu changes the stream. The port
fixes those frames at zero.
