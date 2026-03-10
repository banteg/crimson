# Differential Capture Gaps Memo

## Purpose

This memo records what is still imperfect in the differential capture path after
the recent Frida capture fixes.

The branch goal remains:

- one Frida-private raw capture wire
- one durable replay trace kind: `.cdt`
- one replay schema shared by original/Frida finalize, Python record, and Zig record

This memo is about the remaining places where that goal is still not true, and
what the next schema cut should look like.

## Bottom Line

The current system is closer, but it is still not a single authoritative
capture architecture.

The biggest remaining seams are:

1. `timing_samples` is still a required channel that only one producer really
   emits.
2. RNG rows are still captured with different authority levels across Frida,
   Python, and Zig.
3. The durable trace still throws away some of the most useful original-side
   provenance.
4. The Frida boundary is still too wide: JavaScript and Python both own pieces
   of trace-row normalization.
5. Some Frida timing fields are still inferred even though the authoritative
   globals exist.
6. `diff`, `focus`, and `health` still do not fully exploit the richer trace
   information we already have or want to add.

## What The Current Architecture Gets Right

There are also a few important things that should not be rolled back:

- The branch direction of treating Frida JSONL as an owned contract is right.
- The branch direction of treating `.cdt` as the durable replay artifact is
  right.
- The current move away from movement approximation and toward query-driven
  replay input capture is right.

The decompile supports that last point:

- `analysis/ghidra/derived/hotspots/player_update/functions/004136b0_player_update.c`
  shows gameplay consuming held movement/turn via `grim_is_key_active` and
  alternate single-player bindings via `grim_is_key_down`.
- `analysis/ghidra/derived/hotspots/player_update/functions/00446030_input_primary_just_pressed.c`
  shows primary fire edge detection going through the latch/query path, not
  through post-sim approximation.

So the input side is not the weak link I would revisit first.

## Remaining Gaps

### 1) `timing_samples` Is Still The Largest Contract Mismatch

The schema says `timing_samples` is a required canonical channel:

- `docs/rewrite/cdt-trace-format.md:68-88`

Frida finalize already treats it that way:

- `src/crimson/dbg/frida_finalize.py:374-398`

But the candidate producers do not actually match that contract:

- `src/crimson/dbg/record.py:398-404` writes `timing_samples=[]`
- `crimson-zig/src/cdt_trace.zig:366-372` defaults `timing_samples` to an empty
  slice
- `crimson-zig/src/cdt_trace.zig:711-721` never fills timing samples in the
  built tick record

That means the branch still has a required parity-significant channel that is
not yet a shared producer contract.

This is the first thing that needs an explicit decision:

- either `timing_samples` stays core and all three producers emit the same
  minimum row contract
- or timing moves out of the minimum deterministic replay contract until the
  candidate emitters catch up

If timing stays core, the minimum contract should be small and explicit. For
example:

- one required `gpur_enter` snapshot per tick
- exact `frame_dt_f32`
- exact `frame_dt_ms_i32`
- exact phase name set shared by all producers

### 2) RNG Authority Still Differs Across The Three Producers

Frida currently records exact per-draw rows with original-side provenance:

- `scripts/frida/gameplay_diff_capture.js:3941-3957`

Python records exact per-draw rows, but without provenance:

- `src/crimson/dbg/record.py:84-98`

Zig does not record draws directly. It reconstructs the flat stream by stepping
the LCG across lifecycle checkpoints:

- `crimson-zig/src/cdt_trace.zig:693-721`
- `crimson-zig/src/cdt_trace.zig:1053-1085`

That is still split-brain in the authority model:

- Frida observes calls
- Python records calls
- Zig reconstructs calls

If the goal is one authoritative shared trace contract, all three should record
the same primitive: direct draw rows.

The cleanest next step is:

- keep Frida on direct draw capture
- keep Python on direct draw recording
- change Zig to direct draw recording instead of post-hoc reconstruction

### 3) The Durable Trace Still Loses Useful Original-Side Detail

The trace format still says:

- `phase_markers` remain `list[str]`
- richer raw Frida marker payloads are flattened away

That is explicitly documented in:

- `docs/rewrite/cdt-trace-format.md:87-88`

The current Frida path does exactly that:

- `scripts/frida/gameplay_diff_capture.js:1812`
- `scripts/frida/gameplay_diff_capture.js:4438-4445`

This is one of the reasons the original-side capture is still more useful than
the durable shared trace for root-cause work.

The durable trace should preserve structured phase attribution, not just names.
The RNG memo already points at the right direction:

- `RNG_TRACE_MEMO.md:293-348`

The right replacement is something like `phase_anchors` tied to tick-local RNG
indices or tick-local ranges, for example:

- `{phase: "projectile_update", start_call_index: 11, end_call_index: 19}`
- `{phase: "player_update", tick_call_index: 4}`

That is what turns "draw 17 diverged" into "draw 17 diverged during projectile
update".

### 4) RNG Provenance Fields Are Still Too Weak

Today the canonical row shape only has:

- `caller_static`
- `branch_id`

See:

- `src/crimson/dbg/canonical_channels.py:61-68`
- `crimson-zig/src/cdt_trace.zig:206-213`

Frida currently sets `branch_id` to the same value as `caller_static`:

- `scripts/frida/gameplay_diff_capture.js:3950-3952`

That means `branch_id` is not actually describing a distinct branch or site.

For cross-version unification, the row shape should become more explicit:

- `caller_static_u32: int | None`
- `site_id: str | None`
- `branch_id: str | None`

With those semantics:

- Frida fills `caller_static_u32` exactly when it can
- Frida may also fill `site_id` when we have a stable semantic name
- Python and Zig fill `site_id`
- `branch_id` is only used when one semantic site has multiple branches or
  loops worth distinguishing

### 5) The Frida Boundary Is Still Too Wide

The current docs say JSONL tick rows already carry the finalized replay
channels:

- `docs/frida/gameplay-diff-capture.md:72-78`

And the capture script agrees:

- `scripts/frida/gameplay_diff_capture.js:1756-1821`

But Python finalize still validates and canonicalizes the same row family:

- `src/crimson/dbg/frida_finalize.py:735-765`

That means the trace-row contract is currently owned in two places:

- JavaScript capture-side row shaping
- Python finalize-side typed validation and repacking

That is exactly the kind of boundary that turns into drift over time.

The cleaner split is:

- raw Frida JSONL remains a Frida-private probe wire
- Python finalize is the only canonicalizer into shared `.cdt`

That does not mean the raw wire should be loose. It should still be strict. But
it should be strict about probe rows and authoritative snapshots, not about
duplicating the durable trace assembly logic in JavaScript.

### 6) Some Frida Timing Fields Are Still Inferred Instead Of Read

The decompile shows `gameplay_update_and_render()` using the real globals:

- `analysis/ghidra/raw/crimsonland.exe_decompiled.c:6717-6725`

The data map also already names those globals:

- `analysis/ghidra/maps/data_map.json:3406-3415`

But the current timing row builder derives `time_scale_active_*` and
`time_scale_factor` from `bonus_reflex_boost_timer`:

- `scripts/frida/gameplay_diff_capture.js:3550-3623`

That is weaker than necessary. The authoritative values exist.

For a no-fallback, authoritative-capture policy, the rule should be:

- read `time_scale_active` directly
- read `time_scale_factor` directly
- keep `bonus_reflex_boost_timer` as related state, not as the authority for the
  other two fields

If the authoritative symbol is unavailable, prefer `null` or a hard contract
decision over silent inference.

### 7) The Consumer Layer Still Underuses The Contract

Even where richer information exists, the main consumers still do not fully use
it.

Examples:

- `src/crimson/dbg/channel_compare.py:9-48` compares RNG rows only by call
  index and state/value transitions, not provenance fields
- `src/crimson/dbg/focus.py:47-110` explains checkpoint, RNG, entity, and sim
  state, but not timing samples
- `src/crimson/dbg/health.py:55-93` treats missing channels as issues, but does
  not treat all-empty timing coverage as a contract smell
- `src/crimson/dbg/trace.py:165-166` increments required channel counts
  unconditionally
- `crimson-zig/src/cdt_trace.zig:588-593` likewise reports `timing_samples =
  tick_count` in the footer regardless of whether timing rows are meaningful

So right now it is still possible for the system to look healthier and more
uniform than it actually is.

## What The Unified Target Should Be

The clean target is not "make Python and Zig emit Frida JSONL".

The clean target is:

1. Frida keeps one private raw probe wire.
2. `.cdt` is the only cross-version durable capture format.
3. All three producers emit the same canonical channel schema into `.cdt`.
4. Any original-only extra attribution is preserved in explicit fields, not
   flattened away.

That implies the next trace shape should look more like this:

### Required Core Channels

- `checkpoint`
- `sim_state`
- `entity_samples`
- `rng_stream`
- `timing_samples` only if we explicitly decide timing remains part of the
  minimum parity contract

### `rng_stream`

Keep the deterministic core:

- `tick_call_index`
- `value_15`
- `state_before_u32`
- `state_after_u32`

Extend the provenance shape:

- `caller_static_u32: int | None`
- `site_id: str | None`
- `branch_id: str | None`

### `phase_anchors`

Replace `phase_markers: list[str]` with structured anchors. They do not need to
be complex, but they do need to survive the trip into the durable trace.

### `timing_samples`

Only keep this channel parity-significant if all three emitters can produce the
same minimum contract from authoritative data.

If timing stays core, the minimum shared timing contract should be small and
strict.

## Recommended Execution Order

1. Decide the `timing_samples` policy.
2. If timing stays core, implement the same minimum timing row contract in
   Frida, Python, and Zig.
3. Extend RNG rows with explicit provenance fields and stop using `branch_id` as
   a `caller_static` alias.
4. Add structured `phase_anchors` to the durable trace.
5. Move more of the Frida trace assembly responsibility out of JavaScript and
   into one canonical finalize boundary.
6. Upgrade `diff`, `focus`, and `health` in the same wave so the richer trace
   becomes actionable immediately.

## Acceptance Gates

The next schema wave should not be considered done until all of the following
are true:

- Frida, Python, and Zig all emit the same required channels with the same
  semantics.
- Zig no longer reconstructs RNG draws from checkpoint transitions.
- Timing either has a real shared contract or is explicitly removed from the
  parity-significant minimum.
- Durable traces preserve phase attribution and useful RNG provenance.
- `focus` can explain timing and RNG provenance drift, not just report it.
- `health` can distinguish "channel present" from "channel meaningfully
  populated".

## Bottom Line

The remaining work is not mainly about more hooks. It is about finishing the
contract.

The branch is already pointing at the right architecture:

- private Frida wire
- shared `.cdt`
- typed channels
- deterministic diff

But it still needs one more cleanup wave to become truly authoritative and
truly unified across original, Python, and Zig.
