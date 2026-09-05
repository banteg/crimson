# Audio review — 2026-09-05

Reviewed Python playback, presentation requests, music transitions, settings, and
resource acquisition at `b396f43a050a0c4b537d682292ebf55727d0b68b`. That commit and
the preceding local work have been pushed to `origin/master`.

This is a point-in-time review artifact. The findings below describe that
revision, before implementation; see [FIXES.md](FIXES.md) for their resolution.
Line references and the standalone probes target the reviewed revision. It does
not reopen the already-fixed Reflex Boost batching or quest-reaction timing
findings. Native comparisons below use checked-in recovered functions; no new
original-game capture or listening test was performed.

## Findings

| ID | Priority | Finding | Evidence |
| --- | --- | --- | --- |
| A1 | P2 | Restoring music volume after zero leaves the current tune silent | Production-function reproduction; recovered native state machine |
| A2 | P2 | Death/failure paths never select their native music track | Caller audit against recovered game-over and quest-failed functions |
| A3 | P2 | SFX suppression uses the wrong policy: repeated samples restart freely, distinct events get discarded | Planner/consumer reproduction; recovered per-ID cooldowns |
| A4 | P2 | Sound requests discard position and demo attenuation | Planner/consumer reproduction; exact recovered panned playback |
| A5 | P2 | Failed music decoding is published and queued as a successful load | Real installed raylib decoder reproduction |
| A6 | P2 | Partial audio initialization leaks its acquired native resources | Real archive-loading path with tracked backend allocations and injected failures |

### A1. Preserve the selected playback while global volume is zero

[The zero-volume branch](/Users/banteg/dev/banteg/crimson/src/grim/music.py:302)
stops every stream and removes every `TrackPlayback`. It retains `active_track`
and `game_tune_started`, so increasing the volume has nothing to restart, and
`trigger_game_tune` refuses another start.

This is reachable through the Options slider: play music, set its volume to
zero, leave it there for an update, then raise it. Options only services the
existing music state. The main menu and statistics screen happen to recover
when they become active because they request their track repeatedly; a running
game's first-hit tune does not. A run started with music volume zero has the
same problem after its first hit.

The reproduction starts `gt1_ingame`, mutes, restores volume, and advances 120
updates. There are zero retained playbacks, the backend remains stopped, and a
second trigger returns `None` with the first-hit gate still set.

[Recovered `sfx_update_mute_fades`](/Users/banteg/dev/banteg/crimson/tools/match/scratches/sfx_update_mute_fades/scratch.cpp:17)
stops the buffer at zero global volume but retains the entry and its unmuted
flag. Once volume is positive, the same routine resumes the audible entry and
ramps its volume. Its recovery notes record an exact instruction match.

**Fix direction:** retain playback intent separately from whether the device is
currently playing. Reconcile that intent when volume changes; do not clear the
first-hit gate or choose a new random tune to work around the missing state.
Cover mute/restore both after a track starts and before its initial trigger.

### A2. Restore the game-over and quest-failed track requests

[The game-over update](/Users/banteg/dev/banteg/crimson/src/crimson/modes/base_gameplay_mode.py:734)
updates the result UI without requesting music. Neither the concrete modes'
game-over entry routines nor `GameOverUi` request it. Likewise,
[QuestFailedView.update](/Users/banteg/dev/banteg/crimson/src/crimson/screens/quest_views/quest_failed.py:91)
only calls `update_audio`. Navigation does not supply either missing request.
The previous gameplay tune consequently remains selected; a run without a
started tune remains silent. In the current Python source, `shortie_monk` is
requested only by the statistics screen.

The recovered
[game-over routine](/Users/banteg/dev/banteg/crimson/tools/match/scratches/game_over_screen_update/scratch.cpp:146)
and
[quest-failed routine](/Users/banteg/dev/banteg/crimson/tools/match/scratches/quest_failed_screen_update/scratch.cpp:84)
both request `music_track_shortie_monk_id` while that screen is active and the
track is muted. This retries while a previously used track finishes fading.

**Fix direction:** select that track for both death/failure paths, respecting
the recovered transition guards and fade behavior. Verify an active gameplay
tune transitions to it, a silent run starts it, and quick re-entry eventually
unmutes it. This finding is source-confirmed; the standalone probes do not
exercise a complete interactive death sequence.

### A3. Replace the arbitrary event cutoff with per-ID cooldown handling

[`play_sfx`](/Users/banteg/dev/banteg/crimson/src/grim/sfx.py:183) starts a voice
for every request. Neither it nor `update_audio` maintains a cooldown. In the
opposite direction,
[the presentation planner](/Users/banteg/dev/banteg/crimson/src/crimson/sim/presentation_step.py:417)
keeps only the first four `event_sfx`, regardless of their identities. This
cutoff applies to creature/contact/damage events, while projectile-hit sounds
can pass through without a limit.

The probes demonstrate both sides:

- Six same-tick bullet hits selecting the same sample consume six RNG draws
  and invoke backend playback six times. Native permits one start while that
  ID is cooling down.
- Five distinct supplied death-event IDs become four playback requests; the
  fifth, `TROOPER_DIE_01`, disappears. This is a constructed planner input,
  demonstrating the unconditional cutoff rather than a recorded five-death run.

[Recovered `sfx_play`](/Users/banteg/dev/banteg/crimson/tools/match/scratches/sfx_play/scratch.cpp:13)
and
[`sfx_play_panned`](/Users/banteg/dev/banteg/crimson/tools/match/scratches/sfx_play_panned/scratch.cpp:17)
reject requests by sound ID for 0.05 seconds, or 0.44 seconds for either flamer
ID. [Recovered `audio_update`](/Users/banteg/dev/banteg/crimson/tools/match/scratches/audio_update/scratch.cpp:11)
decrements those timers by `frame_dt_copy`. There is no equivalent global
four-event admission rule in these playback functions.

**Fix direction:** emit the complete ordered request stream and apply native
per-ID admission with explicit timing. Keep distinct native IDs separate even
when their decoded sample bytes are shared. Do not skip the sound-selection
RNG draws when playback is suppressed. Before adding timers, define their
advance point from the recovered frame order and carry that timing through
batched replay application; a wall-clock cooldown would introduce another
frame-partition bug. Test repeated IDs, distinct IDs, both flamer IDs, alias
IDs, zero crossing, and serial versus batched application.

### A4. Carry the sound's spatial and gain inputs through presentation

[Presentation requests](/Users/banteg/dev/banteg/crimson/src/crimson/sim/presentation_step.py:42)
contain only SFX IDs and a shared Reflex Boost timer.
[`plan_hit_sfx`](/Users/banteg/dev/banteg/crimson/src/crimson/sim/presentation_step.py:124)
throws away the hit's coordinates, and
[`AudioBridge`](/Users/banteg/dev/banteg/crimson/src/crimson/world/audio_bridge.py:37)
cannot pass a position or per-request gain to the backend. No Python callsite
sets sound pan. Demo mode influences the first-hit music gate, but not SFX
attenuation.

With identical sound-selection RNG, hits at X=256 and X=768 produce identical
plans and no backend pan calls. In Rush, the same hit also produces an
identical plan with demo mode on or off. The exact recovered
[`sfx_play_panned`](/Users/banteg/dev/banteg/crimson/tools/match/scratches/sfx_play_panned/scratch.cpp:43)
maps those two X values to DirectSound pan -425 and +425 at camera X=0 and
screen width 1024. It also multiplies the requested volume by 0.7 in demo mode.
Weapon fire, projectile impacts, and player/creature damage all call this
native positional path.

**Fix direction:** use a small immutable sound request with ID, position (or
explicitly centered playback), and gain. Capture the relevant camera/viewport
and timing inputs before deferred application. Keep DirectSound-to-raylib pan
and volume conversion in the backend boundary; those APIs do not share the
same numeric units. Preserve the existing deterministic choice/RNG path. Test
left/right positions, camera offsets, centered UI sounds, demo gain, and
deferred application after the world changes.

### A5. Validate decoded handles before publishing a track

[The on-demand loader](/Users/banteg/dev/banteg/crimson/src/grim/music.py:136)
treats only `None` as failure. Installed raylib 5.5.0.4 returns an invalid
`Music` struct when decoding fails. The eager music loader and SFX loader also
lack their respective validity checks.

Using the real decoder on a four-byte file containing `OggS`, the on-demand
loader returns `("corrupt", 0)`, logs `ok`, and stores a stream whose buffer is
null and for which `rl.is_music_valid` returns false. Queuing and triggering it
then sets `game_tune_started=True` even though playback never starts. This
probe opens no audio device and does not substitute decoder results.

The user-facing `snd_addGameTune` command queues every non-`None` result, so a
bad custom file can be selected for the run and leave it silent. At startup,
the same omission permits corrupt declared assets to be reported as loaded.
The concrete decoder reproduction covers music; the analogous SFX omission
is established by source inspection.

**Fix direction:** validate waves, sounds, aliases, and music streams at
acquisition, before setters or registry insertion. Report a meaningful asset
failure and leave the playlist and ID allocator unchanged. Required startup
assets can fail initialization; an invalid optional tune should not enter the
queue. Test actual malformed media as well as successful loading.

### A6. Roll back partial audio acquisition

[`init_audio_state`](/Users/banteg/dev/banteg/crimson/src/grim/audio.py:51)
loads all SFX and then music without an exception cleanup path. If it raises,
`GameResources.open` never receives the new state, so its normal close path
cannot release the partially acquired audio. The debug bootstrap explicitly
catches these errors and continues with `audio=None`, making this more than a
resource leak immediately before process exit.

The probe uses real temporary PAQs and both production archive loaders, with
only native allocation calls substituted by tracked handles. `music.paq`
contains the intro but lacks the next required track. Initialization creates
70 sound sources, 210 aliases, one music stream, and opens the device, then
raises. None of those resources is released and the device is not closed.

There is a second rollback gap inside
[`_load_sample_from_data`](/Users/banteg/dev/banteg/crimson/src/grim/sfx.py:136):
the alias list comprehension can fail after creating the source and earlier
aliases, before any sample is published. Injecting a failure on the second
alias leaves both the source and first alias unreleased. Failure while
creating a sound also bypasses `unload_wave`.

**Fix direction:** make acquisition transactional at both levels. Preflight
required archive entries, register cleanup immediately for each native
allocation, and transfer ownership only after successful initialization.
Release aliases before their source, and track whether this initializer
opened the device. The rollback must also cover the validity failures from
A5. Exercise early and late acquisition failures, then a successful retry.

## Simplifications supported by these findings

1. **One music entry owns its resource and playback state.** The current
   `tracks`, `track_ids`, and `playbacks` dictionaries split one track across
   parallel registries. A small track entry can own the stream, stable console
   ID, source bytes where needed, and fade/mute state. Retain global selection
   and the native first-hit gate explicitly; a stopped device stream should
   not erase the selected entry.
2. **Keep music transitions inside the music API.** Quest completion currently
   reaches into `playbacks`, edits its volume, and calls raylib directly from
   `AudioBridge`. Expose the required start/fade behavior as one music operation
   and remove this second owner of the fade state. Preserve the native rule
   that a still-fading requested track is not immediately unmuted.
3. **Make sample ownership explicit.** Keep unique owned sound resources in
   one collection and the native-ID lookup separately. Shutdown and volume
   updates can then iterate owned samples directly instead of repeatedly
   constructing `set(id(sample))`. Sharing decoded data must not accidentally
   merge the per-native-ID cooldown state introduced for A3.
4. **Remove exception-swallowing dispatch where it hides failure.** Most
   `_safe` music wrappers return a boolean that callers ignore; invalid C
   handles need not raise any Python exception. Validate acquisition, keep
   only justified best-effort cleanup handling, and make playback state
   changes reflect the actual backend contract. This needs no new router or
   general dispatch registry.

Suggested implementation chunks: music state and death-track transitions;
validated resource ownership/rollback; complete sound-request payloads;
native cooldown/admission with deterministic timing coverage. The sound work
needs particular care around RNG consumption and replay batching.

## Validation and limits

- **75 existing targeted tests passed:** music, Reflex Boost pitch, world audio,
  first-hit music triggering, presentation RNG/planning/reactions/granularity,
  quest-failed panels, and high-score navigation.
- [probes.py](probes.py) reproduces A1, A3–A6 through the real Python functions.
  [probe-results.json](probe-results.json) records the observations. Assertions
  describe the reviewed bugs; run this historical probe against the reviewed
  revision. Current regression tests are listed in [FIXES.md](FIXES.md).
- A2 is a source/caller audit against recovered native functions. A3's native
  start count and A4's native pan values are derived from the recovered code,
  not measurements from a live original executable.
- The malformed-media probe uses the installed native decoder. Other playback
  and acquisition probes replace device calls; they establish application
  state and ownership behavior, not audible output or actual allocator sizes.
- No production edits, full repository gate, new Zig review, original-game
  capture, or interactive audio playtest was performed for this review.

Reproduce from the repository root:

```sh
PYTHONPATH=. UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python analysis/reviews/2026-09-05-audio-review/probes.py
```
