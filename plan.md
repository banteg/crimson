# Product Requirements Document: Unifying Delta Time (Resolving the dt "Split Brain")

## 1. Overview and Problem Statement

The codebase currently suffers from a "split brain" regarding delta time (`dt`) representations. Across Python and Zig, the same temporal concepts are represented by overlapping, inconsistently named variables (`dt_frame`, `dt_sim`, `dt_frame_ms_i32`, `dt_sim_ms`, `dt_ms_i32`, etc.). These are recomputed ad-hoc in various layers (e.g., `SurvivalSession`, `RushSession`, `QuestSession`, `step_pipeline.py`).

Replay should carry per-tick `f32` timing directly, so runtime does not branch between derived/default/override dt paths.

### The Native Reality (Decompile-Backed)

Decompile evidence shows a mostly two-variable runtime model in gameplay:
1. `frame_dt` (f32 seconds)
2. `frame_dt_ms` (i32 milliseconds), derived via `__ftol(frame_dt * 1000.0)`

There are also explicit zeroing gates (demo/pause/etc.) where both are set to `0`.

There are three distinct scaling layers to model correctly:
1. Outer frame-loop perk scaling (`REFLEX_BOOSTED`): `frame_dt *= 0.9` in the outer state loop.
2. Gameplay-pass scaling (`bonus_reflex_boost_timer`): in `gameplay_update_and_render`, `frame_dt` is scaled by `_time_scale_factor`, then `frame_dt_ms` is re-derived via `__ftol`.
3. Player-local temporary scaling: in `player_update`, `frame_dt` is temporarily remapped by `(0.6 / _time_scale_factor) * frame_dt` and later restored to the gameplay-pass scale.

Goal: build one canonical timing payload that mirrors this behavior, eliminates local ad-hoc math, and clearly distinguishes:
- unscaled tick cadence
- gameplay-scaled simulation cadence
- deterministic integer-cadence derivation from the same `f32` source

## 2. Goals

- **Structural Simplicity:** Eliminate scattered `dt` derivations and pass one timing object.
- **Native-Accurate Modeling:** Keep integer-cadence paths driven by `__ftol(frame_dt * 1000.0)`-equivalent conversion.
- **Cross-Language Alignment:** Keep Python and Zig naming in lockstep.
- **Deterministic Parity:** No behavior drift from timing conversion/scaling changes.

## 3. Data Model Refactor: `FrameTiming`

Introduce a canonical frame timing struct computed once per deterministic tick entry.

### Open Questions Closed (Decisions)

- `__ftol` semantics for Crimsonland are treated as x87 chop/truncation, not nearest-even.
- `f32` seconds is the primary timing representation in runtime and replay.
- Replay format change is a hard break: no migration path and no legacy replay support.
- Hard break policy applies to replay payloads; trace schema remains explicitly versioned with compatibility handling.
- Timing values do change mid-tick in native flow; sub-tick phase sampling is required for divergence localization.
- `ms`/`ms_i32` values in rewrite code are derived via one helper, not recomputed ad-hoc at call sites.
- Replay format requires per-tick `dt` rows; no runtime fallback/override branch.
- `Replay.dt[tick]` is sampled at `gameplay_update_and_render` entry (`fVar1 = frame_dt`), before gameplay-pass scaling.
- `Replay.dt` validation allows finite non-negative values; `0.0` is valid for explicit native zeroing paths.
- `FrameTiming.compute()` is called after outer-loop writes (`grim_get_frame_dt`, optional `REFLEX_BOOSTED`, optional outer zeroing) and before gameplay-pass scaling.
- `FrameTiming.compute()` receives `time_scale_factor`; `bonus_reflex_boost_timer` is only used by the call site to derive `time_scale_active`.
- `time_scale_factor` must be finite and `> 0.0` whenever `time_scale_active` is true.
- `run_replay_info` must consume the exact same per-tick replay timing rows as `run_replay` (all modes).
- `ReplayRecorder` will always emit per-tick `dt` rows.
- Replay hard break specifics: drop `dt_ms_i32` replay rows from schema and reject old versions rather than migrating.

### Proposed Python Schema

```python
import msgspec


class FrameTiming(msgspec.Struct, frozen=True):
    # Canonical seconds-domain values
    dt: float
    time_scale_active: bool
    time_scale_factor: float
    dt_sim: float

    @property
    def dt_ms(self) -> float:
        return self.dt * 1000.0

    @property
    def dt_ms_i32(self) -> int:
        return ftol_ms_i32(self.dt)

    @property
    def dt_sim_ms(self) -> float:
        return self.dt_sim * 1000.0

    @property
    def dt_sim_ms_i32(self) -> int:
        return ftol_ms_i32(self.dt_sim)

    @property
    def dt_player_local(self) -> float:
        if not self.time_scale_active:
            return self.dt_sim
        return (0.6 / self.time_scale_factor) * self.dt_sim

    @staticmethod
    def compute(
        dt: float,
        *,
        time_scale_active: bool,
        time_scale_factor: float,
    ) -> "FrameTiming":
        # Centralized derivation of all fields.
        # Important: route i32 conversion through a single __ftol-compatible helper;
        # do not mix ad-hoc int()/round() call sites.
        pass
```

### Field Semantics

- `dt`: pre-gameplay-scale cadence (base frame entry).
- `dt_sim`: gameplay-pass cadence consumed by main simulation updates (creatures/projectiles/player/survival/rush/quest and related counters); equals `dt * time_scale_factor` when `time_scale_active`, otherwise `dt`.
- `dt_player_local`: derived player-phase accessor (`(0.6 / time_scale_factor) * dt_sim`) for parity with `player_update`; it is not stored as mutable tick state.
- `dt_ms_i32`: authoritative integer cadence for replayable tick entry (derived from `dt`).
- `dt_sim_ms_i32`: authoritative integer cadence for gameplay-pass consumers.
- `dt_ms` and `dt_sim_ms` are derived convenience accessors only.

### Call-Order Contract (Important)

Deterministic callers must apply native outer-loop behavior before constructing `FrameTiming`:

1. `dt_outer = grim_get_frame_dt()`
2. optional `REFLEX_BOOSTED`: `dt_outer *= 0.9`
3. optional outer zeroing gates
4. derive `time_scale_active` from `bonus_reflex_boost_timer > 0`
5. call `FrameTiming.compute(dt_outer, time_scale_active=time_scale_active, time_scale_factor=time_scale_factor)`

This makes ownership explicit: `compute()` models gameplay-pass and player-local semantics, while outer-loop perk/gating writes stay at the driver boundary.
`FrameTiming` remains immutable for the tick; native mid-tick writes are represented via derived accessors and `timing_samples`, not by mutating the struct.

### Decision: Make `ms`/`ms_i32` Derived Accessors

Decompile evidence indicates native `frame_dt_ms` is consistently re-derived from current `frame_dt` via `__ftol(frame_dt * 1000.0)` whenever `frame_dt` is rescaled, with explicit zeroing paths as the other major case.

For rewrite architecture, a robust simplification is:

- store canonical second-domain fields (`dt`, `dt_sim`) plus scale metadata (`time_scale_active`, `time_scale_factor`)
- expose `ms` and `ms_i32` as properties (or computed accessors) that:
  1. always call a single shared `ftol_ms_i32()` helper on `dt * 1000.0`

This removes duplicate state and avoids drift between `dt` and `dt_ms` fields.

### Cross-Language Conversion Parity (Validated)

To avoid guessing `__ftol` semantics, we validated conversion behavior empirically across Python, Zig, and C++ using shared `f32` bit-pattern inputs.

- Sample size: `160,000` finite `f32` inputs (seeded random + dense dt sweep + edge/tie values).
- Conversion domain: `scaled = f32(dt * 1000.0)`, then convert to i32.
- Result: all three languages can produce identical outputs when the same tie rule is used.

Observed parity outcomes:

- `trunc` mode parity: Python == Zig == C++ (`0` mismatches in corpus).
- `nearest-even` mode parity: Python == Zig == C++ (`0` mismatches in corpus).
- `half-away-from-zero` mode parity: Python == Zig == C++ (`0` mismatches in corpus).
- Expected divergence when mixing rules: C++ `lroundf` vs `lrintf` differed on `.5` ties (e.g. `0.5`, `2.5`, `-1.5`).

Tie examples (`scaled` value -> result):

- Nearest-even: `+0.5 -> 0`, `+2.5 -> 2`, `-1.5 -> -2`
- Half-away: `+0.5 -> 1`, `+2.5 -> 3`, `-1.5 -> -2`
- Trunc: `+0.5 -> 0`, `+2.5 -> 2`, `-1.5 -> -1`

Implementation guidance:

- Binary-specific note (Crimsonland): `__ftol` appears to force x87 chop/truncate before conversion.
  - Evidence: `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:81336-81349`
  - Pattern shows control-word save, OR high control byte with `0x0c` (round-control -> truncate), convert, then restore.
- Therefore, for this game we should lock a truncation contract:
  - C++: `static_cast<int32_t>(scaled_f32)` (or `std::trunc`)
  - Python: `int(math.trunc(scaled_f32))`
  - Zig: `@as(i32, @intFromFloat(@trunc(scaled_f32)))`
- Replay dt encoding contract:
  - Python replay codec quantizes replay `dt` rows to binary32 (`f32`) before write and after load canonicalization.
  - Zig replay codec stores replay `dt` as `[]f32` on wire/runtime.
  - These are interchangeable cross-language because both sides use binary32 values.
- Keep nearest-even/half-away entries above only as cross-language validation modes; they are not the target mode for Crimsonland timing parity.
- Add fixed tie-case tests so this behavior cannot regress silently.

## 4. Execution Plan (Cutover Strategy)

### Phase 1: Lock Conversion Contract and Helper
1. Implement one shared `ftol_ms_i32()` helper with Crimsonland truncation semantics.
2. Replace ad-hoc conversion call sites (`round`, `int`, local formulas) with this helper across replay/sim/dbg channels.
   - First-pass parity-critical replacements:
     - `src/crimson/sim/driver/replay_timing.py` (`resolve_dt_frame_ms_i32`)
     - `src/crimson/sim/sessions.py` (`RushSession.elapsed`)
     - `src/crimson/replay/recorder.py` (`ReplayRecorder._default_tick_dt_ms_i32`)
3. Add explicit tie-case and negative-value tests (`+0.5`, `+2.5`, `-1.5`) to freeze behavior.

### Phase 2: Canonical Timing Type + Nomenclature
1. Define `FrameTiming` in `src/crimson/sim/step_pipeline.py` (or dedicated `timing.py`) with seconds-domain storage and derived accessors.
2. Rename `dt_frame` -> `dt` across drivers/tests.
3. Redesign replay schema to require per-tick `dt` rows (same length as inputs) and remove legacy `dt_ms_i32` rows.
4. Align Zig field names and replay schema in `crimson-zig/src/runtime/replay/step.zig`.
5. Bump replay format version and reject older formats in Python/Zig codecs (hard break, no migration).

### Phase 3: Replay Runner and Info Harmonization
1. Remove `resolve_dt_frame_ms_i32` override plumbing and replace with replay `dt` row lookup (`Replay.dt[tick]`).
2. Ensure `run_replay_info()` consumes replay timing rows exactly like `run_replay()` for survival/rush/quest.
   - Current divergence source to remove:
     - `run_replay()` threads replay dt rows via playback timing config
     - `run_replay_info()` currently constructs empty/default timing config
3. Remove runtime dt override parameters from parity-critical APIs.
4. Update `ReplayRecorder` to always persist per-tick `dt` rows.

### Phase 4: Capture/Finalize/Diff Tooling Harmonization
1. Keep per-tick `dt` as the authoritative replay timing output (sampled at `gpur_enter`).
2. Add structured sub-tick `timing_samples` payload for phase analysis with one row per timing write.
3. Preserve timing evidence through finalize (schema extension required) instead of dropping it.
4. Bump trace schema version for `timing_samples` channel additions and keep explicit compatibility handling for prior trace schema files.
5. Extend `dbg diff`/bisect to compare `timing_samples` and report first timing-phase mismatch.

### Phase 5: Pipeline Wiring
1. Update deterministic step APIs to consume `FrameTiming` instead of separate dt args.
2. Update world/session call graph to use explicit timing fields (`tick` vs `sim` vs `player_local`) only.
3. Remove duplicated local timing derivations once `FrameTiming` is threaded end-to-end.

### Phase 6: Verification and Exit Criteria
1. Run project checks (`just check`) and parity-focused verification commands (`uv run crimson dbg verify`).
2. Re-run deterministic diff artifacts on representative survival/rush/quest captures.
3. Exit only when all are true:
   - `run_replay` and `run_replay_info` agree on elapsed/tick timing for same replay inputs.
   - Runtime timing APIs contain no dt override/fallback branches.
   - Replay codecs reject missing/legacy replay timing rows by version (no implicit fallback path).
   - No remaining ad-hoc dt->ms conversions in parity-critical paths.
   - Recorder-produced replays always include `dt` rows with finite non-negative values and row count equal to input ticks.
   - Timing-channel diff pinpoints first divergence phase on known drift fixtures.

### Phase 7: Author Delta-Time Porting Reference

1. Create a dedicated reference page: `docs/rewrite/parity/delta-time.md`.
2. Link it from `docs/rewrite/parity/index.md`.
3. Treat this page as the source-of-truth for all dt semantics used by Python/Zig rewrites and tooling.

Required sections for `delta-time.md`:

- **Runtime timing model overview**
  - Define `frame_dt` (seconds) vs `frame_dt_ms` (integer milliseconds).
  - Clarify where each value is read/written in native flow.
- **Mutation timeline within one gameplay tick**
  - Outer-loop `REFLEX_BOOSTED` scaling.
  - `gameplay_update_and_render` gameplay-pass scaling + `frame_dt_ms` re-derive.
  - Player-local remap/restore inside `player_update`.
  - End-of-function restore behavior.
  - Zeroing/gating paths and their conditions.
- **Conversion contract (`__ftol`)**
  - Document Crimsonland-specific truncation/chop semantics.
  - Include tie examples (`+0.5`, `+2.5`, `-1.5`) and expected integer outputs.
  - Provide exact Python/Zig/C++ equivalents.
- **Units and field semantics for rewrite**
  - `dt` vs `dt_sim` and derived `dt_player_local`.
  - `*_ms` convenience vs `*_ms_i32` authoritative cadence.
  - Replay row semantics (`Replay.dt` required, `*_ms_i32` derived via helper).
- **Consumer map**
  - Which systems consume second-domain dt.
  - Which systems consume integer-ms cadence (survival/rush/quest timers/cooldowns, etc.).
- **Replay/capture/debug semantics**
  - What capture/replay records per tick (`dt`) and why.
  - Where sub-tick timing samples are needed for divergence localization.
  - How finalize/diff pipelines should preserve/compare timing evidence.
- **Porting pitfalls and invariants**
  - Common drift causes (mixed rounding rules, duplicate derivations, missing restore ordering).
  - Invariants implementers must assert in tests.

Acceptance criteria for this documentation task:

- A new contributor can implement `ftol_ms_i32()` and required replay dt row plumbing without reading decompile first.
- The page includes direct references to decompile anchors already listed in this PRD.
- The page includes at least one end-to-end “tick timeline” worked example with before/after dt values.

## 5. Decompile Reference Map (For Implementers)

Use these exact anchors while implementing:

### Core Gameplay Scaling and Restore

- `gameplay_update_and_render` @ `0x0040aab0`
  - Save original dt: `fVar1 = frame_dt`
    - `analysis/ghidra/raw/crimsonland.exe_decompiled.c:6717`
    - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:8725`
  - Gameplay scale + i32 derivation:
    - `frame_dt = _time_scale_factor * frame_dt`
    - `frame_dt_ms = __ftol(frame_dt * 1000.0)`
    - `analysis/ghidra/raw/crimsonland.exe_decompiled.c:6723-6725`
    - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:8744-8748`
  - Gating zero path:
    - `frame_dt_ms = 0; frame_dt = 0.0`
    - `analysis/ghidra/raw/crimsonland.exe_decompiled.c:6742-6743`
    - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:8802-8803`
  - `time_scale_active` derives from `bonus_reflex_boost_timer` and timer decrements by `frame_dt`
    - `analysis/ghidra/raw/crimsonland.exe_decompiled.c:6824-6827`
    - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:8954-8960`
  - End-of-function restore:
    - `frame_dt = fVar1; frame_dt_ms = __ftol(fVar1 * 1000.0)`
    - `analysis/ghidra/raw/crimsonland.exe_decompiled.c:6925-6927`
    - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:9224-9225`

### Outer Loop Perk Scaling (`REFLEX_BOOSTED`)

- `console_hotkey_update` @ `0x0040c1c0`
  - Perk gate + gameplay-state check then `frame_dt *= 0.9`
  - Re-derive `frame_dt_ms = __ftol(frame_dt * 1000.0)`
  - `analysis/ghidra/raw/crimsonland.exe_decompiled.c:7565-7573`
  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:10061-10096`

### Player-Local Temporary dt Mapping

- `player_update` @ `0x004136b0`
  - Local remap entry when `time_scale_active`:
    - `frame_dt = (0.6 / _time_scale_factor) * frame_dt`
    - `analysis/ghidra/raw/crimsonland.exe_decompiled.c:12151-12152`
    - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:16125-16130`
  - Local restore back to gameplay-pass scale:
    - `frame_dt = time_scale_factor * frame_dt * 1.6666666...`
    - constants: `data_46f33c=0.6`, `data_46f50c=1.6666666...`
    - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:17904-17909`
    - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:97757`
    - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:97875`

### Integer-Cadence Consumers (`frame_dt_ms`)

- Quest timeline/timers use `frame_dt_ms` arithmetic:
  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:6079-6109`
- Survival cadence uses `frame_dt_ms` arithmetic:
  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:6152`
  - `analysis/binary_ninja/raw/crimsonland.exe.bndb_hlil.txt:8965-8966`

## 6. Sub-Tick Timing Trace Plan (Divergence Localization)

To precisely find timing divergence causes, we should trace `frame_dt` and `frame_dt_ms` at sub-tick phase boundaries, not only once per tick.

### Why This Is Needed

- `frame_dt` and `frame_dt_ms` are mutated inside a single gameplay tick.
- A single per-tick snapshot can hide where drift begins (e.g., player-local remap vs gameplay-pass scale vs restore timing).

### Required Trace Fields Per Sample

- `tick_index`
- `gameplay_frame`
- `phase`
- `write_kind` (`frame_dt_write` | `frame_dt_ms_write` | `snapshot`)
- `frame_dt_f32`
- `frame_dt_ms_i32`
- `frame_dt_ms_f32`
- `time_scale_active`
- `time_scale_factor`
- `bonus_reflex_boost_timer`
- `mode_fn` (nullable)
- `player_index` (nullable)

### Canonical Mutation Markers (Native)

Emit a `timing_samples` row for every write to `frame_dt` or `frame_dt_ms` in the gameplay frame path:

1. `outer_get_frame_dt`
   - `frame_dt = grim_get_frame_dt()` in `console_hotkey_update` (`0x0040c1d7`)
2. `outer_reflex_boosted_scale` (conditional)
   - `frame_dt = frame_dt * 0.9` (`0x0040c4e7`)
3. `outer_rederive_ms`
   - `frame_dt_ms = __ftol(frame_dt * 1000.0)` (`0x0040c517`)
4. `outer_console_zero_dt` (conditional)
   - `frame_dt = 0.0` (`0x0040c5b6`)
5. `gpur_enter` (snapshot; replay `dt` source)
   - `fVar1 = frame_dt` at `gameplay_update_and_render` entry (`0x0040aab0`)
6. `gpur_after_gameplay_scale` (conditional)
   - `frame_dt = _time_scale_factor * frame_dt` (`0x0040ab11`)
7. `gpur_after_gameplay_scale_ms` (conditional)
   - `frame_dt_ms = __ftol(frame_dt * 1000.0)` (`0x0040ab22`)
8. `gpur_zero_gate_ms` (conditional)
   - `frame_dt_ms = 0` (`0x0040abae`)
9. `gpur_zero_gate_dt` (conditional)
   - `frame_dt = 0.0` (`0x0040abb4`)
10. `player_local_scale_enter` (conditional)
    - `frame_dt = (0.6 / _time_scale_factor) * frame_dt` in `player_update` (`0x00413e13`)
11. `player_local_scale_restore` (conditional)
    - `frame_dt = time_scale_factor * frame_dt * 1.6666666...` (`0x00414f5f`)
12. `gpur_restore_dt`
    - `frame_dt = fVar1` (`0x0040b1fd`)
13. `gpur_restore_ms`
    - `frame_dt_ms = __ftol(fVar1 * 1000.0)` (`0x0040b208`)

### Existing Capture Support vs Needed Additions

Already present in `scripts/frida/gameplay_diff_capture.js`:
- Tick envelope (`gameplay_update_and_render` enter/leave)
- Mode enter/leave samples with `frame_dt_ms_i32`
- Before/after globals with timing summary

Need to add:
- `timing_samples` channel (array of marker rows) emitted per tick, analogous to RNG sample streams.
- Internal `player_update` probes at `0x00413e13` and `0x00414f5f`.
- Explicit write markers for outer-loop and `gpur_*` timing writes listed above.

### Invariants to Assert Per Tick

- At `gpur_after_gameplay_scale`: `frame_dt_ms_i32 == ftol_ms_i32(frame_dt_f32 * 1000.0)` unless on zero-gate path.
- Across `mode_enter` -> `mode_leave`: integer cadence should remain consistent for a given phase.
- `player_local_scale_restore` should return `frame_dt` to gameplay-pass scale (not entry `dt`).
- At `gpur_after_restore`: `frame_dt` / `frame_dt_ms` should match pre-scale baseline (`fVar1` path), except explicit zeroing paths.
- `Replay.dt[tick]` should equal `gpur_enter.frame_dt_f32` for that tick.

### Divergence Triage Rules

- First mismatch at `gpur_after_gameplay_scale`:
  - likely gameplay-pass scaling or `ftol` conversion parity issue.
- Match through mode phases, mismatch in `player_local_*`:
  - likely player-local remap/restore implementation issue.
- Match through player-local phases, mismatch in mode outputs:
  - likely integer-cadence consumer mismatch (quest/survival/rush timers/cooldowns).
- Match until `gpur_before_restore`, mismatch at `gpur_after_restore`:
  - likely restore ordering or final `frame_dt_ms` recompute mismatch.

### Practical Comparison Key

Compare rows by:
- `(tick_index, phase, player_index?)`

Stop at first mismatch and classify by phase using the triage rules above.
