Below is a PRD proposal for a **Crimson Debugger** tool, grounded in the concrete workflows and pain-points that show up repeatedly in your repo:

* **Existing differential workflows/tools**: `crimson original verify-capture`, `divergence-report`, `bisect-divergence`, `focus-trace`, `creature-trajectory`, `visualize-capture`, plus the caching daemon (`diagnostics_cache.py` / `diagnostics_daemon.py`).
* **Existing artifacts & formats**: Frida `gameplay_diff_capture` stream format (`crimson_capture_msgpack_v1\n`, `CAPTURE_FORMAT_VERSION=5` in `crimson/original/schema.py` + loader in `crimson/original/capture.py`), replay format (`.crd`), and replay checkpoints sidecar (`.chk`) (`crimson/replay/checkpoints.py`).

I’m going to define a debugger that:

1. introduces a **unified debug trace format** that *any implementation* (original-capture conversion, Python, future Zig/Rust) can produce,
2. provides a **fast query/diff engine** over that trace, and
3. wraps the common “find first mismatch → bisect → focus tick → trace entity” loop into an integrated workflow.

---

# PRD: Crimson Debugger

## Implementation Progress

- [x] Chunk 1: CDT container/schema + `crimson dbg import-capture` + `crimson dbg health`
- [x] Chunk 2: `crimson dbg record` (Python runner profiles + CDT writer integration)
- [x] Chunk 3: `crimson dbg diff` + `crimson dbg bisect` + parity policy + JSON reports
- [x] Chunk 4: `crimson dbg tick` + `crimson dbg entity` + `crimson dbg query` + `crimson dbg focus`
- [x] Chunk 5: `crimson dbg viz` + final workflow wiring + documentation/tests cleanup
- [x] Chunk 6: PRD parity remediation (`rng_stream_head` in record output, full profile `micro_traces` + richer `event_heads`, viz tick stepping controls, regression tests)
- [x] Chunk 7: AGENTS guideline cleanup (remove redundant casts/coercions in typed debugger internals; keep validation at boundaries)
- [x] Chunk 8: Forward-compat schema decode (allow unknown CDT fields in core dbg structs + regression tests)
- [x] Chunk 9: Shared debugger channel helpers (dedupe `as_object_dict`/`as_object_list`/RNG key extraction across diff/focus/query/viz)

## 1) Background

Crimson already has strong deterministic simulation and differential tooling:

* **Golden sources**:

  * Frida “original” captures (`gameplay_diff_capture.*.msgpack.zst`) parsed by `crimson.original.capture.load_capture`.
  * Python deterministic headless run output via replay checkpoints (`crimson replay verify-checkpoints`, `crimson.original.verify.verify_capture`).
  * “Oracle” mode emits JSON states (`crimson oracle`) but is not a scalable or indexed debugging substrate.

* **Core workflow today (as documented + implemented)**:

  1. Gate on capture quality (`capture-health`) to ensure you have high-signal telemetry (micro rows, lifecycle data, dt sources).
  2. Run `divergence-report` to find earliest sustained divergence and get context: window rows, RNG marks, lead attribution, run summary events.
  3. Run `bisect-divergence` to produce a compact repro bundle around `first_bad_tick`.
  4. Run `focus-trace` to dig into the tick: RNG alignment (prefix match / missing tail), collisions/near misses, projectile/creature presence diffs, callsite distributions.
  5. If needed, trace a specific creature/projectile (`creature-trajectory`) and/or visually inspect (`visualize-capture`).

This is an excellent set of tools, but:

* it’s **format-fragmented** (capture schema vs replay checkpoints vs ad-hoc JSON reports),
* it’s **not designed as a unified “time-travel debugger” substrate**, and
* it will become more painful when you add a third implementation (Zig/Rust) that also needs to plug into the same diff/debug story.

## 2) Problem Statement

You need a **unified debug format + debugger** that supports:

* **Cross-implementation** comparisons:

  * original capture → python
  * python → zig/rust
  * zig → rust
  * any “candidate” vs “golden”

* **Fast interrogation**:

  * “show me state at tick 75”
  * “trace creature slot 32 over ticks 160..210”
  * “show RNG marks + call stream around first divergence”
  * “diff the projectile pool at tick 187”

* **Reproducible, stable artifacts**:

  * a single artifact that can be checked into `analysis/` or attached to an issue and deterministically re-opened later.
  * schema versioning and portability across machines/OS.

The missing piece is a **debug trace format** that is:

* deterministic + portable across languages,
* random-access friendly (tick + entity queries),
* extensible (you can add new channels without breaking older readers),
* composable into “repro bundles”.

## 3) Goals

### Primary goals

1. Define **Crimson Debug Trace (CDT)**: a versioned, language-neutral debug trace format.
2. Provide a **Crimson Debugger** tool that:

   * imports original captures into CDT,
   * records CDT from a headless run (Python now, Zig/Rust later),
   * supports **fast queries** and **high-signal diffs**,
   * can generate compact **repro bundles** automatically.
3. Integrate existing workflows into a cohesive “debugger” UX:

   * mismatch detection
   * bisection
   * focus trace
   * entity trajectories
   * visualization hooks

### Secondary goals

* Provide a stable **report schema** for divergence output (JSON) so sessions can be machine-compared.
* Provide optional **daemon / cache** mode (like current diagnostics daemon) for interactive speed.

## 4) Non-goals

* Not a general-purpose game editor.
* Not a replacement for your existing Frida capture pipeline (it remains the golden source).
* Not a full source-level debugger (no stepping through Python bytecode); it’s a **simulation-state debugger**.

## 5) Personas & Use Cases

### Persona A: “Port engineer” (Python → Zig/Rust)

* Needs to verify that a new implementation matches Python or original captures.
* Wants minimal friction to produce traces and diff them.

### Persona B: “Parity investigator”

* Needs to quickly isolate root cause:

  * RNG drift vs state drift vs ordering drift
  * projectile collisions vs AI movement edge cases
* Uses tools like today’s `divergence-report` + `focus-trace`, but wants faster, more unified navigation.

### Persona C: “CI / regression gate”

* Needs deterministic pass/fail checks.
* When failing, needs a compact repro artifact and a stable report.

## 6) Key Product Concepts

### 6.1 “Trace” vs “Database”

You likely want two layers:

1. **CDT file** (portable interchange): immutable, versioned, compressed, chunked + indexed.
2. **Local index / cache** (optional): built from CDT for very fast queries:

   * could be a sidecar (`.cdt.idx`) or a local cache DB (sqlite/duckdb/arrow) keyed by trace fingerprint.
   * mirrors what you already do with `diagnostics_cache.py`, but generalized.

This keeps the on-disk interchange format simple and cross-language, while still enabling speed.

---

# 7) Crimson Debug Trace Format (CDT)

## 7.1 Requirements

CDT must:

* represent enough state to support the existing high-signal diff workflows:

  * checkpoint-style fields (score/kills/players/bonus timers/perks)
  * RNG marks + partial call stream head
  * sampled entities (creatures/projectiles/secondary/bonuses)
  * event heads (projectile spawn/hit queries, creature spawn/death/damage, perk apply, sfx, mode_tick, etc.)
* support fast access:

  * random access by tick
  * range scans over ticks
  * entity lineage/trajectory queries
* be writable from:

  * Python (now)
  * Zig/Rust (future) with minimal dependencies
* be schema-versioned and forward-compatible:

  * unknown channels can be skipped safely

## 7.2 File container: CDT v1

### Proposal: chunked, indexed, zstd-compressed blocks

A single-file format that supports **random access without reading/decompressing the entire file**.

**Layout (conceptual):**

* Header:

  * magic: `b"crimson_debug_trace_v1\n"`
  * format version: u32 = 1
* One **META** chunk (uncompressed or compressed):

  * run metadata (implementation, git sha, replay header, capture fingerprint, etc.)
  * channel manifest
* N **TICK_BLOCK** chunks:

  * each chunk covers a contiguous tick range, e.g. 256 ticks/chunk (tunable)
  * chunk payload is msgpack/CBOR/protobuf (see below), optionally zstd-compressed
* One **FOOTER** chunk:

  * tick block index: `[ {start_tick, end_tick, file_offset, compressed_len, uncompressed_len, checksum} ... ]`
  * overall stats summary (tick_count, first/last tick, etc.)
  * optional secondary indices (entity → tick ranges) if you want them in-file

### Encoding choices

Given your existing tooling:

* you already use **msgspec + msgpack** and **zstandard** heavily.
* msgpack libraries exist for Rust and Zig.
  So CDT v1 can reasonably be:
* **payload encoding**: msgpack (maps/struct-like)
* **compression**: zstd per chunk
* **checksums**: xxhash64 or sha256 per chunk (choose based on desired cost)

*(If you later want a stronger “schema evolution” story, you can swap payload encoding behind the same container.)*

## 7.3 Data model

### 7.3.1 Trace meta

**TraceMeta** (top-level):

* `trace_format_version`: 1
* `trace_schema_version`: 1 (for semantic schema evolution)
* `created_utc`: ISO string
* `producer`:

  * `impl`: `"original_capture" | "python" | "zig" | "rust" | "other"`
  * `impl_version`: freeform string (git sha, tag)
  * `platform`: os/arch
* `source`:

  * if from capture: capture fingerprint `{path?, sha256, size, mtime_ns, capture_format_version}`
  * if from replay: replay fingerprint `{sha256, tick_rate, seed, mode_id, quest_level,...}`
* `channels`: list of channels included with per-channel schema versions and parameters
* `tick_range`: `{start_tick, end_tick, tick_count}`
* `config`:

  * knobs that impact determinism (e.g. preserve_bugs, dt overrides, inter_tick_rand_draws, aim_scheme overrides)
  * MUST be serialized because it changes interpretation

### 7.3.2 Tick record

Each tick record is composed of **channels**; channels are optional.

Core tick header:

* `tick_index: i32`
* `elapsed_ms: i32` (or optional)
* `dt_ms_i32: i32?` (critical for timing parity debugging)
* `mode_id: i32`
* `phase_markers: []` (if available; from capture this exists)

#### Channel: `checkpoint`

A “verification checkpoint” equivalent, aligned to `ReplayCheckpoint`:

* `rng_state: u32` (or i64 if needed)
* `score_xp: i32`
* `kills: i32`
* `creature_count: i32`
* `perk_pending: i32`
* `players[]`: pos/health/weapon/ammo/xp/level
* `bonus_timers: {bonus_id -> ms}`
* `perk_snapshot`: choices + per-player counts
* `events_summary`: hits/pickups/sfx counts
* `state_hash`: string (or u64)
* `command_hash`: string (or u64)

*(This is your “baseline diff substrate”; it is what `verify-capture`/`verify-checkpoints` uses today.)*

#### Channel: `rng_marks`

Your stage marks like those used in `DEFAULT_RNG_MARK_ORDER`:

* `marks: {string -> i32}`
* `total_calls: i32`
* `seq_first/seq_last`: optional
* `seed_epoch`: optional
* `outside_before_calls/dropped`: optional

#### Channel: `rng_stream_head`

A bounded, structured head of RNG calls (like capture’s `CaptureRngHeadEntry`):

* entries with:

  * `tick_call_index`
  * `value_15` and/or full `u32`
  * `state_before/after` (optional)
  * `caller_static` (stable symbol or address)
  * `caller` (full callsite or symbol)
  * `branch_id` (optional; used in your bisect/focus workflows)

This supports:

* prefix-match / missing-tail detection (your current high-signal tool)
* callsite distribution by tick

#### Channel: `entity_samples`

A set of pool samples similar to `CaptureSamples`:

* `creatures[]` (index/active/type_id/hp/pos/flags/ai_mode/link_index/heading/target_heading/orbit/ai7_timer_ms…)
* `projectiles[]`
* `secondary_projectiles[]`
* `bonuses[]`

**Important addition:** *entity lineage id* (see 7.4).

#### Channel: `event_heads`

A bounded list of structured event heads aligned to capture:

* `projectile_spawn`, `secondary_projectile_spawn`
* `projectile_find_query`, `projectile_find_hit`
* `creature_spawn`, `creature_damage`, `creature_death`, `creature_lifecycle_digest`
* `perk_apply`, `perk_delta`
* `bonus_spawn`, `bonus_apply`
* `sfx`
* `mode_tick` / `quest_timeline_delta`
* input queries / key edges if useful

This channel is needed to preserve the “branch evidence” you rely on in `bisect-divergence` and `focus-trace`.

#### Channel: `micro_traces`

For your high-value “movement root cause” telemetry (what `capture-health` gates on):

* creature_update_micro angle-approach rows
* creature_update_micro window rows
* (future) projectile collision micro traces if desired

#### Channel: `presentation_trace` (optional, later)

If you want to unify `effects.py`/blood/decal RNG consumers, you can record:

* “presentation RNG consumers” counters (like your focus-trace rng callsite distribution output)
* this is probably better as a derived index rather than raw trace at first

## 7.4 Entity identity (critical)

Your current samples identify entities primarily by **pool index** (`CaptureCreatureSample.index`, etc.). That’s fine until:

* slots are reused, and
* post-divergence, pool allocation order differs.

CDT should define a stable “entity uid” for tracing:

* **uid = (pool_kind, pool_index, generation)**

Where `generation` increments each time that pool slot transitions from inactive → active.

How to compute generation:

* In Python simulation: increment a counter per slot on spawn/activate.
* In capture import: infer from lifecycle digest and/or spawn events:

  * for creatures: `CaptureCreatureLifecycleDigest.added_ids` / `added_head`
  * for projectiles: spawn heads include `index`
  * for bonuses: spawn heads include `index`

Store:

* `uid: u64` (packed)
* also store `spawn_tick`, `despawn_tick?` if known (helps indexing)

This enables:

* “trace this creature’s life” instead of “trace slot 32 that got reused 4 times”.

---

# 8) Crimson Debugger Tool

## 8.1 Product surface

A single top-level entrypoint, ideally:

* `crimson dbg ...`

with both:

* CLI commands (first-class)
* Python API for scripting (mirrors how you already build complex diagnostics)
* optional daemon mode for fast iteration

## 8.2 Core commands

### 8.2.1 Import/record

#### `crimson dbg import-capture <capture.msgpack.zst> --out <trace.cdt>`

* Converts Frida `CaptureFile` (format v5) to CDT.
* Also writes:

  * trace meta with capture fingerprint + capture config
  * the replay reconstruction parameters it inferred/used (seed, tick_rate, quest level inference, dt overrides availability)

**Acceptance criteria**

* For a given capture, `import-capture` is deterministic byte-for-byte (same output on same inputs).
* Emits trace health summary (see 8.4).

#### `crimson dbg record <replay.crd> --impl python --out <trace.cdt> --profile <...>`

* Runs the deterministic simulation and records CDT.
* Profiles:

  * `minimal`: checkpoints only (fast, small)
  * `standard`: checkpoints + rng marks + entity samples (default)
  * `full`: standard + event heads + micro traces (heavier)

**For Zig/Rust later**

* the same interface conceptually exists, but implementation calls external binary:

  * `crimson dbg record <replay.crd> --impl ./zig_runner --out trace.cdt`

### 8.2.2 Diff and bisect

#### `crimson dbg diff <golden.cdt> <candidate.cdt> [options]`

Outputs:

* first mismatch tick
* mismatch kind classification:

  * rng_stream_mismatch
  * command_hash mismatch
  * state_hash mismatch
  * checkpoint field mismatch (with diffs)
  * entity sample mismatch (presence/fields)
* context window (before/after)
* run summary events (if available)
* optional JSON report output

This should essentially subsume today’s:

* `verify-checkpoints` / `verify-capture`
* `divergence-report`

…but can initially call into those implementations internally and gradually unify.

#### `crimson dbg bisect <golden.cdt> <candidate.cdt> --out repro.cdbg`

* Binary-search first bad tick (like `bisect-divergence`)
* Emit a **repro bundle** CDT limited to a tick window around `first_bad_tick`:

  * window ticks + rng stream head + branch event heads + entity samples
* This “repro CDT” becomes the standard artifact you attach to issues.

### 8.2.3 Inspect/query

#### `crimson dbg tick <trace.cdt> <tick>`

Print a “tick summary”:

* checkpoint (players/kills/xp/perk pending/bonus timers)
* rng marks summary
* event_counts + top event heads
* entity counts (active creatures/projectiles/bonuses)

Optionally:

* `--json` for machine output

#### `crimson dbg entity <trace.cdt> <entity_uid> [--ticks a..b]`

Shows:

* lifecycle (spawn tick, despawn tick)
* per-tick key fields (pos/hp/flags/ai mode/owner etc depending on kind)

#### `crimson dbg query <trace.cdt> "<expression>"`

Two-tier approach:

* v1: a small query DSL (safe subset) to filter/aggregate:

  * examples:

    * `ticks where checkpoint.kills != prev(checkpoint.kills)`
    * `creatures where type_id == 0x2a and hp < 10`
* v2: optionally SQL over a derived local DB cache

### 8.2.4 Focus tools (integrate existing “focus-trace”)

#### `crimson dbg focus <golden.cdt> <candidate.cdt> --tick N`

Produces a structured focus report:

* RNG alignment:

  * prefix match length
  * missing tail count
  * first mismatching callsite/value
  * top callsites by count in tick
* Entity presence diffs:

  * creatures (missing/extra + nearest neighbors by pos)
  * projectiles (missing/extra + owner/type)
* Collision/near-miss analysis (where possible):

  * If both traces have enough info, run the same collision probe logic you currently do in `focus_trace.py`.
  * Otherwise degrade gracefully to entity diffs + RNG diff.

This is essentially a unification layer over your existing `focus_trace` logic, with CDT as the substrate.

### 8.2.5 Visualization

#### `crimson dbg viz <golden.cdt> <candidate.cdt> [--tick N]`

Extend `crimson.original.capture_visualizer` into a more general “trace visualizer”:

* render both runs’ entity samples
* show divergence vector lines
* overlay tick/time UI + run summary events
* allow stepping tick-by-tick

This gives you a “time travel viewer” that works for:

* original vs python
* python vs rust

## 8.3 Outputs & Report Schemas

### Human-readable console output

* Must remain “grep-friendly” and session-log-friendly (your session docs rely on this).

### JSON report output

Standardize the structure:

* `meta`: trace fingerprints, impl IDs, config
* `result`: ok/diverged, kind, tick
* `summary`: run summary events
* `window`: per-tick rows like you print today
* `diffs`: structured diffs (checkpoint fields, rng, entities)
* `artifacts`: optional references (repro bundle path)

This allows:

* comparing two divergence reports automatically
* CI to store structured failure artifacts

## 8.4 Trace health / telemetry gating

A generalized version of `summarize_capture_health()` for CDT:

* `crimson dbg health <trace.cdt>`

Reports:

* which channels present
* counts / coverage (micro trace rows, event head counts, rng head availability, dt coverage)
* “ok_for_movement_root_cause” equivalent gating

This formalizes what you already do for captures, but now for any trace producer.

---

# 9) Diff Semantics and “Parity Policies”

You already have domain-specific allowances in `crimson.original.verify` and `crimson.original.diff`:

* float tolerances (`float_abs_tol`)
* special-case 1ms bonus timer jitter for certain IDs
* allowances for capture creature_count lag vs sample count
* one-tick kills lag

The debugger must formalize these into a **Parity Policy** concept:

## 9.1 ParityPolicy

A versioned policy that defines:

* which fields are authoritative in which producer pairs
* tolerances by field path (float abs tol, int jitter tolerance)
* known “capture artifacts” allowances
* entity matching heuristics

Examples:

* `policy=original_vs_python_default`
* `policy=python_vs_rust_strict`
* `policy=python_vs_rust_relaxed_float32`

This prevents “mysterious” diffs and makes CI consistent.

## 9.2 Diff layers

Implement diff in layers, in order of increasing cost:

1. command_hash mismatch (if present)
2. state_hash mismatch
3. checkpoint field diffs (structured, bounded count)
4. rng mark diffs (first mismatching stage)
5. rng stream diff (head alignment)
6. entity samples diff (presence + key fields)
7. event head diff (bounded)
8. micro trace diff (if enabled)

Each layer emits a “lead”:

* “first_rng_mark=ws_after_projectiles”
* “missing_native_tail=1 at caller_static=0x0043d4bd”
* “creature uid=(creature,32,g=5) diverged: heading drift crosses pi boundary”
  …mirroring what your session logs show is actually actionable.

---

# 10) Architecture

## 10.1 Components

### (A) `crimson.debug.trace` (new)

* CDT schemas (msgspec structs)
* reader/writer
* chunk indexer
* fingerprinting

### (B) `crimson.debug.importers`

* capture importer: `CaptureFile -> CDT`
* replay runner recorder: `Replay -> CDT` (Python now)

### (C) `crimson.debug.query`

* tick/entity lookups
* optional derived indices
* optional cache/db layer

### (D) `crimson.debug.diff`

* parity policies
* diff engine (layers)
* bisection
* repro bundle generation

### (E) `crimson.debug.ui`

* CLI entrypoints
* optional daemon process (like diagnostics daemon)
* visualization hooks (reuse grim/raylib viewer)

## 10.2 Reuse existing code

A lot of your current logic becomes “engines” behind the debugger:

* `crimson.original.capture` remains the authoritative capture parser.
* `crimson.original.verify` and `crimson.original.diff` become a subset of `crimson.debug.diff` (or are wrapped).
* `divergence_report`, `bisect_divergence`, `focus_trace`, `creature_trajectory` become:

  * either subcommands in `crimson dbg`
  * or analyzers that operate on CDT.

## 10.3 Caching / daemon mode

You already have:

* `diagnostics_daemon.py` and session registry caching captures and derived results.

Debugger should optionally provide:

* `crimson dbg daemon` (or auto-start like today)
* caches:

  * parsed CDT blocks
  * per-trace indices
  * derived diffs / focus results keyed by (traceA fingerprint, traceB fingerprint, policy, options)

The key is: interactive workflows should not constantly reparse and resimulate.

---

# 11) Performance Requirements

## 11.1 Targets (v1)

* Open CDT meta: < 50ms typical
* Query single tick (random access): < 20ms once index is loaded (excluding first-time decompression cost)
* Diff a 10k tick run using checkpoints + hashes: < 2s typical on dev machine
* Bisect first bad tick: O(log N) tick checks; should complete in < ~10–20 “tick block reads” worth of work (depending on block size)

## 11.2 Storage targets

* `minimal` traces should be comparable in size to `.chk` sidecars (order of MBs).
* `standard` traces should be significantly smaller than full captures, but large enough for entity diffs.
* `full` traces can be large; expected to be used selectively or trimmed into repro bundles.

---

# 12) Migration Plan

## Phase 0: Spec + scaffolding

* Add CDT schema definitions + reader/writer + chunk container.
* Add `dbg import-capture` that converts capture → CDT standard profile.
* Add `dbg health` for CDT.

## Phase 1: Make CDT useful immediately

* Add `dbg diff` that compares:

  * imported-capture CDT vs python-recorded CDT
* Implement baseline diff layers:

  * command_hash/state_hash/checkpoint fields/rng marks
* Implement `dbg bisect` producing repro CDT.

## Phase 2: Replace the most-used workflows

* Add `dbg focus` (wrap/port focus_trace features to work from CDT).
* Add `dbg entity` trajectory (wrap/port creature_trajectory patterns).
* Add `dbg viz` (generalize capture visualizer to load CDT pairs).

## Phase 3: Cross-impl + CI integration

* Define “trace producer contract” for Zig/Rust:

  * required channels for `minimal` / `standard`
  * canonical field definitions (float32 bits)
* Add CI job:

  * run python impl → produce CDT
  * run zig impl → produce CDT
  * `dbg diff` gate
  * on failure: store repro CDT + JSON report

---

# 13) Risks & Open Questions

## 13.1 Biggest risks

1. **Schema drift / ambiguity** across implementations
   Mitigation: write a strict spec + conformance tests (golden CDT fixtures) and require parity policies be explicit.

2. **Entity matching in divergence scenarios**
   Post-divergence, pool indices shift. Without entity uid lineage, diffs become noisy.
   Mitigation: require `generation` in CDT and implement heuristic matching (type_id + nearest pos) for diagnostics, but keep “uid-based” as primary.

3. **Trace size explosion**
   Full state every tick is huge.
   Mitigation: channel profiles + chunked format + repro bundle workflow as the default “share artifact”.

4. **“Too many knobs”** (dt overrides, inter-tick RNG draws, aim schemes)
   Mitigation: store all knobs in TraceMeta; ensure diff reports show them.

## 13.2 Open questions (but you can proceed without blocking)

* Should CDT embed the replay inputs, or reference them by sha?
  My suggestion: **reference by sha** + optionally embed for repro bundles.
* Should the “query engine” be SQL-based in v1?
  My suggestion: **no**; start with fast structured APIs + simple query DSL, add SQL later if needed.
* Do you want CDT to support “multi-run” bundles (A+B in one file)?
  My suggestion: start with one run per CDT; repro bundles can include both runs later if desired.

---

# 14) Success Metrics

* **Time-to-root-cause** reduction: fewer steps from divergence to actionable lead.
* **Artifact portability**: a repro CDT attached to an issue can be opened and interrogated by anyone without reconstructing state.
* **Cross-implementation readiness**: Zig/Rust can emit CDT and be diffed with the same tooling.
* **CI signal quality**: fewer “false negatives” and fewer noisy diffs; failures come with a repro bundle and focus report.

---

# 15) What I’d build first (high leverage, minimal disruption)

If you want a “v1” that delivers immediate value and stays aligned with your current workflow, the smallest meaningful slice is:

1. **CDT container + schema** with channels: `checkpoint`, `rng_marks`, `rng_stream_head`, `entity_samples`, `event_heads`.
2. `dbg import-capture` (capture → CDT).
3. `dbg record --impl python` (replay runner → CDT).
4. `dbg diff` + `dbg bisect` producing a repro CDT.
5. `dbg tick` + `dbg entity` queries.

That already gives you:

* a portable substrate to diff Python vs Zig/Rust later,
* a faster path to inspect “what changed at tick N” without re-running ad-hoc tools,
* and a standard artifact (`repro.cdt`) that replaces today’s “JSON repro bundle” in a more extensible way.

---

If you want, I can also propose a concrete **CDT v1 schema sketch** (field-by-field, msgspec structs, exact chunk header/footer structs, and a set of conformance fixtures derived from one of your existing capture test builders) — but the above PRD is the “product contract” level that should let you start breaking this into issues and implementing iteratively.
