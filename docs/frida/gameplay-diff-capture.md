---
tags:
  - status-validation
  - frida
  - differential-testing
---

# Gameplay differential capture

`scripts/frida/gameplay_diff_capture.js` records the original executable using
raw capture format 22. The host finalizes each completed run into the same
formats used by the rewrite debugger:

- CDT container 2, schema 15
- CRD replay 16
- a sibling `.rng_evidence.json` diagnostic report
- a typed `.evidence.msgpack.zst` native-evidence sidecar

Recordings are disposable. Only this version tuple is supported; regenerate a
capture after any owned format changes.

## Attach through the host

The host is the normal entry point because it attaches, collects the JSONL, and
finalizes it in one workflow:

```text
uv run --with frida==17.15.4 python scripts/frida/gameplay_diff_capture_host.py \
  --process crimsonland.exe \
  --script scripts\frida\gameplay_diff_capture.js \
  --output-dir C:\share\frida
```

`just frida-gameplay-diff-capture` wraps the same command. Pass host arguments
after `--`, for example:

```text
just frida-gameplay-diff-capture -- --keep-raw
```

Terminal gameplay transitions close the active run before the game-over or
quest-results screen. A clean stream may end immediately after `run_end`;
there is no session trailer to race process teardown. The host never appends or
repairs lifecycle rows. EOF with an active run is a hard recapture error.

Useful host options:

- `--raw-path <path>`: override the JSONL path in both host and injected agent
- `--finalize-only`: finalize an existing JSONL without attaching; requires
  `--raw-path`
- `--keep-raw`: retain the producer-private JSONL after successful finalization

For a direct attach:

```text
frida -n crimsonland.exe -l scripts\frida\gameplay_diff_capture.js
```

The default raw path is
`C:\share\frida\gameplay_diff_capture.jsonl`. Run the host afterwards with
`--finalize-only --raw-path ...` to produce replay-grade artifacts.

## Lifecycle contract

The JSONL stream is ordered and typed:

1. one `session_start`
2. one or more completed `run_start` -> `tick` -> `run_end` sequences
3. EOF immediately after any completed `run_end`

Capture format, session identity, row order, mode/quest identity, tick counts,
and lifecycle counters must agree. Run-local `tick_index` and session-global
`global_tick_index` advance exactly one at a time. Unknown fields, capture
errors, an empty run, or a missing `run_end` invalidate the whole capture.

Finalization deliberately has no partial-run or salvage mode. A truncated
capture lacks evidence and must not be made to look like a valid behavioral
comparison.

## Run start

The most recent session `crt_srand` seed is stale by the time a run begins:
menus and prior startup work may already have consumed draws. The capture
latches the real CRT state immediately before the run's first terrain draw,
counts every bootstrap draw, and records the exact state where bootstrap ends.
These are written as `rng_state_before_bootstrap`, `rng_bootstrap_calls`, and
`rng_state_after_bootstrap`.

The state-transition frame consumes a discarded shared-CRT draw at `0x0040cac7`
after that setup window and before the first gameplay update. The agent records it as a
`game_frame_rng_advance` replay prelude operation. Finalization only validates
the captured operation against the exhaustive outside-RNG state chain; it never
invents a missing operation.

Finalization verifies that advancing the before-state by the captured call
count produces the after-state. It uses the before-state for `ReplayHeader.seed` and records
`run_start_seed_source = "rng_state_before_bootstrap"` in CDT metadata. It also copies
captured creature-pool residue to `ReplayHeader.initial_creature_pool`. Together
these make the generated CRD start from the observed native run boundary rather
than an inferred clean state.

`run_start.settings` also records the exact replay identity used for the run:
tick rate, retry count, hardcore flag, detail preset, violence flag, world size,
and the complete decoded game-status blob. Finalization does not supply fallback
values. It sets `preserve_bugs=true` because the producer is the original game.

Only Survival, Rush, and Quest runs are replay-grade. Demo, Typ-o, Tutorial, and
unknown modes fail explicitly; their exact driving data is not captured by this
format.

## Tick contract

Every tick has the canonical schema 15 channels:

- `replay_step`
- `checkpoint`
- `sim_state`
- `entity_samples`
- `rng_stream`
- `timing_samples`

`replay_step` is the replay-driving authority. Its wire order is `dt`, `inputs`,
`prelude`, `postlude`, `commands`. There is no sibling `replay_inputs`
transport field. The prelude contains named native frame-RNG advances and
between-tick perk operations that must run before simulation. The
postlude contains native `perks_generate_choices` calls observed late inside
`gameplay_update_and_render`, after the mode and simulation updates. Their RNG
rows remain in that tick's canonical `rng_stream` while replay executes the
postlude with tick RNG tracing still active. Terrain/bootstrap RNG is owned by
replay initialization and excluded from the outside-frame bag. Each remaining
outside draw carries a `replay_operation_index`: top-level frame draws must map
to a `game_frame_rng_advance` operation and use native caller `0x0040cac7`, while
draws inside a captured perk operation map to that operation. Missing ownership,
an invalid caller for a frame operation, or a draw count that disagrees with a
frame operation invalidates the capture. `commands` is reserved for Typ-o input
and is therefore empty in supported Frida runs.

Perk choice snapshots always contain the seven native slots exactly, including
zeros and duplicates, plus the actual dirty bit. A pick records its exact
selection index in `0..6`. A choice refresh inside the native tick is a separate
`perk_menu_open` postlude operation; a refresh between ticks is represented in
the next tick's prelude. An outside-tick selection pick likewise remains in the
next tick's prelude.

Input intent is captured before simulation rather than inferred from player
movement. `sim_state.players` separately records the resulting `heading`,
`move_speed`, `move_phase`, `aim`, and `aim_heading`, so a diff can distinguish
bad input capture from bad movement integration.

Each tick also requires exactly one `gpur_enter` timing row. Its f32 delta must
equal `replay_step.dt`, and its integer millisecond delta must equal the tick's
`dt_ms_i32`.

Canonical checkpoints deliberately contain only producer-neutral evidence.
Effective projectile hits exclude owner collisions, pickup counts are retained,
and `sfx_count`, SFX/hit heads, and death rows are zero or empty. Their complete
native values remain in the typed evidence sidecar. Quest elapsed time uses the
native `quest_spawn_timeline`; native `time_played_ms` and the summed replay
clock are retained beside it for diagnosis.

## RNG evidence

The capture reads the real CRT RNG state from per-thread data instead of relying
on a software mirror. This exposes draws that bypass the `crt_rand` hook:

- canonical `rng_stream` rows carry value, before/after state, call index, and
  required numeric caller for Frida captures
- tick boundary samples record RNG state entering and leaving the gameplay
  update
- diagnostic bags count hooked draws outside gameplay-update windows
- every in-tick and between-tick LCG chain must be complete and contiguous

Any invalid transition, missing draw, dropped outside row, or unowned outside
draw rejects the capture. `run_end.trailing_prelude` retains operations observed
after the final gameplay update solely so finalization can prove ownership of
the tail RNG chain; those operations are not added to the replay. Finalization writes
`gameplay_diff_capture.<mode>.run<k>.rng_evidence.json`. The report summarizes
the exact bootstrap boundary and outside callers.

Caller attribution is diagnostic. If two traces have the same draw values and
state transitions but different caller labels, `dbg diff` reports
`rng_caller_attribution_mismatch` under `channel_first_diagnostics`; it does not
declare behavioral divergence.

## Finalized output

Each completed run produces a matching artifact set:

- modes: `gameplay_diff_capture.<mode>.run<k>.cdt`, `.crd`,
  `.rng_evidence.json`, and `.evidence.msgpack.zst`
- quests: `gameplay_diff_capture.quest_<major>_<minor>.run<k>.cdt`, `.crd`,
  `.rng_evidence.json`, and `.evidence.msgpack.zst`

The four files publish as one rollback-safe bundle. If any replacement fails,
the previous complete bundle is restored and the raw JSONL is retained.

The rich sidecar is evidence format 2: one zstd frame containing little-endian
u32-length-prefixed MessagePack `header`, `tick`, and `footer` rows. Its header
binds the bundle to the session/module/pointer hashes and the raw/CDT/CRD
SHA256 values. Missing or unknown typed fields, trailing bytes, and concatenated
zstd frames are rejected.

Run these checks before investigating behavior:

```text
uv run crimson dbg verify
uv run crimson dbg health <native.cdt>
uv run crimson dbg record <run.crd> --out <rewrite.cdt>
uv run crimson dbg health <rewrite.cdt>
uv run crimson dbg diff <native.cdt> <rewrite.cdt>
```

The diff reports the earliest divergent tick, the first mismatch for each
channel over the selected range, and f32 bit/ULP details for finite float
differences. Use `dbg bisect` and `dbg focus` to narrow the window, then
`dbg tick`, `dbg entity`, or `dbg query` for local evidence.

`just frida-copy-share` copies the entire share directory. `just
frida-import-raw` imports the CDT, CRD, RNG report, and typed evidence files
together so native diagnostics are not lost.

## Capture fixtures

`just capture-fixtures-import <captures_dir>` imports current finalized pairs
into `tests/fixtures/captures/`. It preserves each full contiguous CDT, verifies
every trace block, the replay hash and tick range against the CRD sidecar, the
current Frida version, and the replay-aligned `rng_state_before_bootstrap` seed source.
It then writes versioned provenance to `manifest.json`. A stale or inconsistent
pair aborts the import instead of being skipped.

The importer and fixture tests accept only the current capture/CDT/CRD contract.
Old checked-in recordings should be deleted and replaced with a fresh format 22
capture. Fixture parity is a strict diff assertion; known mismatches are not
hidden behind a blanket `xfail`.
