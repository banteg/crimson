# Product Requirements Document: Unifying Delta Time (Resolving the dt "Split Brain")

## 1. Overview and Problem Statement

The codebase currently suffers from a "split brain" regarding delta time (`dt`) representations. Across Python and Zig, the same temporal concepts are represented by overlapping, inconsistently named variables (`dt_frame`, `dt_sim`, `dt_frame_ms_i32`, `dt_sim_ms`, `dt_ms_i32`, etc.). These are recomputed ad-hoc in various layers (e.g., `SurvivalSession`, `RushSession`, `QuestSession`, `step_pipeline.py`).

Replay telemetry also injects an integer capture override (`dt_frame_ms_i32`) that is threaded through many layers.

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
- capture override behavior for replay parity

## 2. Goals

- **Structural Simplicity:** Eliminate scattered `dt` derivations and pass one timing object.
- **Native-Accurate Modeling:** Keep integer-cadence paths driven by `__ftol(frame_dt * 1000.0)`-equivalent conversion.
- **Cross-Language Alignment:** Keep Python and Zig naming in lockstep.
- **Deterministic Parity:** No behavior drift from timing conversion/scaling changes.

## 3. Data Model Refactor: `FrameTiming`

Introduce a canonical frame timing struct computed once per deterministic tick entry.

### Proposed Python Schema

```python
import msgspec


class FrameTiming(msgspec.Struct, frozen=True):
    # Unscaled tick cadence (entry dt)
    dt_tick: float
    dt_tick_ms: float
    dt_tick_ms_i32: int

    # Gameplay-pass simulation cadence (after gameplay scale factor)
    dt_sim: float
    dt_sim_ms: float
    dt_sim_ms_i32: int

    # Optional: player-local temporary movement cadence (when native remaps dt in player_update)
    dt_player_local: float

    @staticmethod
    def compute(
        dt_tick: float,
        *,
        time_scale_active: bool,
        reflex_boost_timer: float,
        dt_tick_ms_i32_override: int | None = None,
    ) -> "FrameTiming":
        # Centralized derivation of all fields.
        # Important: route i32 conversion through a single __ftol-compatible helper;
        # do not mix ad-hoc int()/round() call sites.
        pass
```

### Field Semantics

- `dt_tick*`: pre-gameplay-scale cadence (base frame entry).
- `dt_sim*`: gameplay-pass cadence consumed by main simulation updates (creatures/projectiles/player/survival/rush/quest and related counters).
- `dt_player_local`: only for player movement section parity when `time_scale_active` is true.
- `*_ms_i32` values are authoritative for integer-cadence systems; `*_ms` float fields are derived convenience values.

### Simplification Candidate: Make `ms` Derived Properties

Yes, this can be simplified further.

Decompile evidence indicates native `frame_dt_ms` is consistently re-derived from current `frame_dt` via `__ftol(frame_dt * 1000.0)` whenever `frame_dt` is rescaled, with explicit zeroing paths as the other major case.

For rewrite architecture, a robust simplification is:

- store canonical second-domain fields (`dt_tick`, `dt_sim`, optional `dt_player_local`)
- store replay-capture overrides separately (nullable)
- expose `ms` and `ms_i32` as properties (or computed accessors) that:
  1. use override when present
  2. otherwise call a single shared `ftol_ms_i32()` helper on `dt * 1000.0`

This removes duplicate state and avoids drift between `dt` and `dt_ms` fields while preserving capture-parity exceptions.

## 4. Execution Plan (Cutover Strategy)

### Phase 1: Establish the Type
1. Define `FrameTiming` in `src/crimson/sim/step_pipeline.py` (or dedicated `timing.py`).
2. Add one shared conversion helper for `frame_dt -> ms_i32` parity (the helper all codepaths must call).
3. Align Zig field names in `crimson-zig/src/runtime/replay/step.zig`.

### Phase 2: Consolidate Nomenclature

- Rename `dt_frame` -> `dt_tick` across drivers/tests.
- Rename replay override `dt_frame_ms_i32` -> `dt_tick_ms_i32_override` to encode intent.

### Phase 3: Single Instantiation

1. Rename `resolve_dt_frame_ms_i32` to `resolve_dt_tick_ms_i32_override` in `src/crimson/sim/driver/replay_timing.py`.
2. In deterministic sessions, remove per-call-site derivations (`dt_sim_ms`, `dt_frame_ms`, `base_dt_ms_i32`, etc.).
3. Construct `FrameTiming` once and thread it through step execution.

### Phase 4: Pipeline Wiring

- Update `run_deterministic_step` to consume `FrameTiming` instead of separate `dt` args.
- Update `GameWorld.update` and downstream call graph to use `timing` fields explicitly (`tick` vs `sim` vs `player_local`).

### Phase 5: Verification and Parity Assertions

- Run project checks (`just check` and parity-focused verification commands).
- Re-run deterministic diff artifacts (`uv run crimson dbg verify`).
- Add/extend tests around:
  - gameplay scaling (`time_scale_active` true/false)
  - replay override precedence
  - integer ms conversion edge cases (single helper behavior)

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
- `frame_dt_f32`
- `frame_dt_ms_i32`
- `frame_dt_ms_f32`
- `time_scale_active`
- `time_scale_factor`
- `bonus_reflex_boost_timer`
- `mode_fn` (nullable)
- `player_index` (nullable)

### Canonical Phase Sequence (Native)

1. `gpur_enter`
   - Hook: `gameplay_update_and_render` on-enter (`0x0040aab0`)
2. `gpur_after_gameplay_scale`
   - Immediately after gameplay scaling and `frame_dt_ms` re-derive
   - Decompile anchors: `0x0040ab11` / `0x0040ab22`
3. `mode_enter` / `mode_leave`
   - Around `survival_update` / `rush_mode_update` / `quest_mode_update`
4. `player_enter` / `player_leave`
   - Around `player_update` (`0x004136b0`)
5. `player_local_scale_enter`
   - Internal probe at local remap (`0x00413e13`)
6. `player_local_scale_restore`
   - Internal probe at local restore (`0x00414f5f`)
7. `gpur_before_restore`
   - Right before end-of-function restore (`frame_dt = fVar1`)
8. `gpur_after_restore`
   - After `frame_dt`/`frame_dt_ms` restore (`0x0040b1fd` / `0x0040b208`) or function leave

### Existing Capture Support vs Needed Additions

Already present in `scripts/frida/gameplay_diff_capture.js`:
- Tick envelope (`gameplay_update_and_render` enter/leave)
- Mode enter/leave samples with `frame_dt_ms_i32`
- Before/after globals with timing summary

Need to add:
- Internal `player_update` probes at `0x00413e13` and `0x00414f5f`
- Explicit `gpur_after_gameplay_scale` and `gpur_before_restore` phase samples

### Invariants to Assert Per Tick

- At `gpur_after_gameplay_scale`: `frame_dt_ms_i32 == ftol_ms_i32(frame_dt_f32 * 1000.0)` unless on zero-gate path.
- Across `mode_enter` -> `mode_leave`: integer cadence should remain consistent for a given phase.
- `player_local_scale_restore` should return `frame_dt` to gameplay-pass scale (not entry `dt_tick`).
- At `gpur_after_restore`: `frame_dt` / `frame_dt_ms` should match pre-scale baseline (`fVar1` path), except explicit zeroing paths.

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
