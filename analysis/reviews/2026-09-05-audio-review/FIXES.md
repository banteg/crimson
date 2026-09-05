# Audio review resolution — 2026-09-06

All six findings in [REPORT.md](REPORT.md) are implemented. That report and its
probes remain evidence for the reviewed revision; maintained behavior is
specified in `docs/re/static/reference/audio.md` and
`docs/rewrite/deterministic-step-pipeline.md`.

| Finding | Resolution | Regression coverage |
| --- | --- | --- |
| A1 | One music entry owns its stream, source bytes, and mute/fade/pause state. Zero volume preserves the selected tune and first-hit gate. Paused streams resume; stopped unmuted streams restart. | `tests/grim/test_grim_music.py`: volume zero before/after selection, restore without another RNG draw, muted tracks, stopped streams, and fades. |
| A2 | Game-over and quest-failed updates request `shortie_monk` until the screen starts closing. Quest completion uses the music API's fade-in operation. | `tests/screens/test_game_over_mode_actions.py`, `tests/screens/test_quest_failed_panel.py`, result re-entry and fade tests in `test_grim_music.py`, shared post-plan tests. |
| A3 | All ordered requests reach the audio sink. Cooldowns are per native ID, including distinct IDs sharing sample data, and advance after each tick using the native pre-slow-motion frame delta. | `tests/grim/test_grim_sfx_playback.py`, `tests/sim/test_presentation_step.py`, `tests/sim/test_presentation_reactions.py`: duplicate hits still consume six RNG draws but start one voice; distinct events survive the former cap; serial/batched backend traces and session digests agree. |
| A4 | Immutable requests retain position and gain. The sink supplies each tick's viewport, demo attenuation, and captured Reflex Boost timer. The backend converts DirectSound channel attenuation into raylib pan and gain. | Pan/channel-level, active-voice volume, centered reuse, ranged-creature gain, demo, camera-offset, and deferred-application tests. |
| A5 | Wave, source, alias, and music handles are validated before use/publication. Invalid optional tunes neither enter the registry nor consume an ID. | Real installed decoders reject malformed Ogg/WAV input; injected validity failures cover remaining acquisition stages. |
| A6 | Acquisition registers cleanup immediately and transfers ownership only on success. Shutdown releases aliases before sources, retains streaming bytes through decoder teardown, and closes only an owned device. | `tests/grim/test_grim_audio_resources.py`: allocation failures, missing archive entries, rollback, reload/retry, borrowed devices, and repeated shutdown. |

Implementation also corrected the existing Reflex Boost frequency conversion.
Disassembling the original `__ftol` at `0x00461054` shows `or ah, 0x0c`, `fldcw`,
and `fistp`: it explicitly selects truncation, so a timer of 0.25 gives 38,587 Hz,
not 38,588 Hz. Pan and volume conversion likewise preserve float32 operation
boundaries and truncation.

The structural changes remove parallel music registries, ignored `_safe`
wrappers, direct fade-state edits in `AudioBridge`, and repeated sound-resource
identity deduplication. `SfxRequest` is a pure data schema; it does not introduce
another dispatch registry or alter replay checkpoint wire fields.

## Commits

- `b61f5161c`: retained music intent and restored result transitions.
- `29421ff38`: validated decoded assets and made acquisition transactional.
- `dd94af9b2`: distinguished paused music from stopped streams.
- `73005dfff`: migrated spatial sound requests and added native cooldowns,
  channel conversion, timing, and regression coverage.

## Validation boundaries

Final validation passed:

- `just check`: lint/import/type/docs checks, native artifact closure checks,
  matching regression checks, and structural rule tests; 2,709 Python tests
  passed with 10 skipped, and all 135 snapshots passed.
- The same gate passed all 652 Zig tests and the ReleaseFast and WASM builds.
- `uv build`: source distribution and wheel built successfully.
- `uv run --no-sync zensical build`: documentation site built successfully.

The regressions exercise production planners, sessions, archive loaders, and
sound admission. Device calls are substituted for playback/ownership checks;
malformed-media checks use the actual installed decoder. No new original-game
audio capture or live listening test was performed.

The backend retains the port's explicit zero-volume SFX mute, bounded shared
voice pool, and per-voice gain state. This work establishes the reviewed rules
and deterministic application, not sample-exact parity with DirectSound's
16-buffer ownership and mixing behavior.
