Here’s what “split brain / duplicate” looks like in *your* schema, based on the msgspec.Struct inventory you pasted, and what I’d collapse.

## What “split brain” means here

In schema/design terms:

- **Duplicate** = two (or more) structs that carry the *same* conceptual payload (often identical fields), maintained separately.
- **Split brain** = the same concept exists in multiple “authoritative” representations across subsystems (net vs replay vs debug vs CLI vs runtime), so they inevitably **drift** (field names, defaults, units, container types), and you end up with conversion glue, mismatches, and subtle bugs.

In a deterministic game with netcode + replays + tracing, some duplication is inevitable (runtime vs wire vs debug). The problem is when you have **4–6 parallel versions** of the same thing with no single canonical “source of truth”.

------

## High-confidence duplicates / split brain hotspots

### 1) Net protocol: legacy vs relay are parallel universes

You essentially have the same session/lobby concepts twice:

**Struct pairs that are \*the same concept\* (sometimes very close field sets):**

- `legacy_protocol.Hello` ↔ `relay_protocol.ClientHello`
- `legacy_protocol.Welcome` ↔ `relay_protocol.ClientWelcome`
- `legacy_protocol.LobbySlot` ↔ `relay_protocol.RelaySlot`
- `legacy_protocol.LobbyState` ↔ `relay_protocol.RoomState`
- `legacy_protocol.Ready` ↔ `relay_protocol.RoomReady`
- `legacy_protocol.MatchStart` ↔ `relay_protocol.RoomStart`
- `legacy_protocol.InputSample/InputBatch` ↔ `relay_protocol.RbInputSample/RbInputBatch`
- `legacy_protocol.ResyncBegin/Chunk/Commit` ↔ `relay_protocol.RbResyncBegin/Chunk/Commit`

**Exact duplicate:**

- `legacy_protocol.Packet` and `relay_protocol.Packet` have identical headers (`seq`, `ack`, `reliable`, `message`).

**What to collapse**
Create a **shared net “wire model”** layer and have both protocols embed or alias it.

Example idea:

```py
class SessionSettings(msgspec.Struct, frozen=True):
    mode_id: int
    player_count: int
    quest_level: str
    tick_rate: int
    input_delay_ticks: int
    preserve_bugs: bool
    netcode_mode: NetcodeMode = "rollback"
    rollback_max_ticks: int = 8

class SlotState(msgspec.Struct, frozen=True):
    slot_index: int
    connected: bool
    ready: bool
    is_host: bool
    peer_name: str
```

Then:

- `LobbyState` and `RoomState` just differ by top-level naming (`session_id` vs `room_code`, etc.) while both contain `SessionSettings` + `slots: list[SlotState]`.
- `Packet` becomes *one* shared type imported by both protocols.

This reduces drift and makes it obvious what must match for determinism.

------

### 2) “Status snapshot” exists 3+ times (plus a commented 4th)

You explicitly have split brain here:

- `legacy_protocol.StatusSnapshot` (“intentionally mirrors … persistence.save_status.GAME_STATUS_STRUCT”)
- `replay.types.ReplayStatusSnapshot`
- `dbg.canonical_channels.SnapshotStatus`

They overlap on:

- `quest_unlock_index`
- `quest_unlock_index_full`
- `weapon_usage_counts` (but **list vs tuple** differs)
  …and the legacy one adds:
- `quest_play_counts`, `mode_play_*`, `game_sequence_id`, `unknown_tail`.

**Why this matters**
This data is used as an *authoritative progress / unlock state* injected into net sessions and replays. Having multiple slightly-different shapes is prime “desync by schema mismatch” territory.

**What to collapse**
Pick *one canonical* “progress/status” struct for the game, then:

- Net messages use it directly.
- Replay headers store it directly.
- Debug snapshot stores it directly (or stores a strict subset derived from it).

Also normalize:

- container choice, don’t mix list and tuple across “wire formats” unless conversion is automatic and guaranteed.

A pragmatic split:

- `GameStatus` (canonical, immutable-ish)
- `GameStatusWireV1` (exact wire format + versioned)
- `GameStatusDebug` (optional extra fields)

Right now you have: `StatusSnapshot`, `ReplayStatusSnapshot`, `SnapshotStatus`, *and* an implied `GAME_STATUS_STRUCT`. That’s too many “sources of truth”.

------

### 3) Telemetry/benchmark/reporting types are duplicated across runtime vs CLI payloads

These are extremely clear duplicates (same fields, different names/modules):

- `sim/driver/setup.py: RunResult` ↔ `cli/replay.py: _RunResultPayload`
- `sim/driver/replay_info.py: ReplayInfoTimelineEvent` ↔ `cli/replay.py: _ReplayInfoEventPayload`
- `sim/driver/replay_benchmark.py: BenchmarkAggregate` ↔ `cli/replay.py: _BenchmarkAggregatePayload`
- `sim/driver/replay_benchmark.py: BenchmarkSample` ↔ `cli/replay.py: _ReplayBenchmarkSamplePayload`
- `sim/driver/replay_benchmark.py: ReplayProfileHotspot` ↔ `cli/replay.py: _ReplayBenchmarkProfileHotspotPayload`
- `sim/driver/render_telemetry.py: RenderTelemetryFrameSnapshot` ↔ `cli/replay.py: _ReplayRenderTelemetryFramePayload`
- `sim/driver/replay_benchmark.py: ReplayRenderTelemetryArtifacts` ↔ `cli/replay.py: _ReplayRenderTelemetryArtifactsPayload`
- …and corresponding `Summary`/`Result` wrappers

**What to collapse**
This is the easiest win: stop defining “payload twins”.

Options:

1. **Make the driver structs the payload structs** (they’re already msgspec.Struct) and reuse them in CLI output.
2. If the CLI needs different field names or extra formatting, add `to_payload()` conversion, but don’t clone whole schemas.

This also improves backward compatibility: you version one schema, not two.

------

### 4) Vector/geometry has a wire/debug duplicate, plus raylib vectors leak in

You have:

- `grim.geom.Vec2` (rich type with methods, defaults, canonical!)
- `dbg.canonical_channels.SnapshotVec2` (wire-ish strict type)
- plus `rl.Vector2` appears directly in some contexts (`PerkMenuContext.mouse`, `Vec2.to_rl()` exists, etc.)

**Split brain symptom**
Same conceptual “2D point” appears in three representations.

**What to collapse/simplify**

- Choose a canonical internal math type: probably `Vec2`.
- For wire/debug: use `Vec2` (if you can tolerate extra methods/defaults), or
- Avoid embedding `rl.Vector2` inside “data schema” structs unless they’re strictly render-only. `PerkMenuContext.mouse: rl.Vector2` is a red flag because it couples UI/data to a backend type and prevents reuse/serialization.

A clean boundary:

- runtime + sim: `Vec2`
- render boundary: convert to `rl.Vector2` at draw call time
- debug/wire:  reuse Vec2

------

### 5) HUD flags are duplicated inside HUD context

You have:

- `HudRenderFlags` (five booleans)
- `HudRenderContext` repeats those same booleans (`show_health`, `show_weapon`, …) with defaults.

That’s a direct duplication.

**What to collapse**
Either:

- drop `HudRenderFlags` and just use the booleans in `HudRenderContext`, or
- make `HudRenderContext` contain a single `flags: HudRenderFlags` and remove the duplicate fields.

If you want defaults, put defaults in one place only.

------

### 6) UI layout structs show repeated patterns (and at least one same-name duplication)

You literally have `_DropdownLayout` defined twice:

- `frontend/panels/controls.py:_DropdownLayout`
- `game/high_scores_view/view.py:_DropdownLayout`

They overlap in core fields (`pos`, `width`, `header_h`, `row_h`, `rows_y0`, `full_h`) but one adds arrow/text fields.

**What to collapse**
Make a base + extension (composition is easiest with msgspec):

```py
class DropdownLayoutBase(msgspec.Struct, frozen=True):
    pos: Vec2
    width: float
    header_h: float
    row_h: float
    rows_y0: float
    full_h: float

class DropdownLayoutChrome(msgspec.Struct, frozen=True):
    arrow_pos: Vec2
    arrow_size: Vec2
    text_pos: Vec2
    text_scale: float
```

Then the two panels share `DropdownLayoutBase`, and only the one that needs chrome uses the extra struct.

Also, a *lot* of layouts repeat `scale`, `base_pos`, `label_pos` patterns. Consider a small library of:

- `PanelLayout(scale, panel_top_left, base_pos, …)`
- `TextBlockLayout(pos, scale, line_h, …)`
  …and compose.

------

## Medium-confidence split brain (conceptually duplicative, but may be intentional)

### 7) “Options/Context” structs overlap heavily

Examples:

- `ProjectileUpdateOptions` vs `StepPipelineOptions` vs `CreatureUpdateOptions`
- overlapping knobs: `world_size`, `detail_preset`, `fx_toggle`, `rng/rand`, `players`, etc.

**Potential simplification**
Introduce a small shared config object that flows through sim:

```py
class SimTuning(msgspec.Struct, frozen=True):
    world_size: float
    detail_preset: int
    fx_toggle: int
    damage_scale_by_type: dict[int, float] | None = None
```

Then each subsystem-specific options struct contains `tuning: SimTuning` plus its extras.

This is especially valuable because “world_size/detail/fx” are determinism-adjacent. Keeping them unified reduces accidental divergence.

------

### 8) “preserve_bugs” is everywhere (and therefore split brain prone)

I see `preserve_bugs` in:

- `ViewContext`
- `GameConfig`
- `LanSessionConfig`
- net: `Hello`, `Welcome`, `MatchStart`, `RoomCreate`, `RoomState`, `RoomStart`
- replay: `ReplayHeader`

That’s a classic split-brain toggle: if any layer forgets to propagate it, determinism breaks.

**What to collapse**
Put it inside the shared `SessionSettings` / `SimTuning` / `DeterminismSettings` struct, and embed that everywhere instead of repeating the boolean.

------

### 9) Owner identity is split between `OwnerRef` and “legacy int owner_id”

You have a good new model:

- `OwnerRef(kind, index, local_host)` with conversions to/from legacy ints

But lots of places still store:

- `owner_id: int` (`CreatureDeath`, debug projectile samples, etc.)

**Simplification**
For new schemas (replays/debug/net vNext), consider storing `OwnerRef` directly, and only convert to legacy ints at compatibility boundaries. That makes the schema self-describing and reduces “magic negative int” logic scattered around.

------

## Cross-cutting simplifications that will pay off

### B) Replace free-form `kind: str` with `Literal[...]` / tagged unions

A lot of structs have `kind: str` with a comment listing allowed values:

- `DemoTrialOverlayInfo.kind`
- `QuestRunOutcome.kind`
- `_TimerRef.kind`
- etc.

This is schema-level fragility: typos become runtime bugs.

**Suggestion**
Use `Literal` unions or msgspec tagged unions (`tag=`) consistently so the schema enforces correctness.

------

### C) Decide “tuple vs list” policy by layer

Right now you mix tuple/list across similar schemas:

- replay uses tuples for `weapon_usage_counts`
- net uses lists
- debug uses lists

Pick:

- runtime/mutable: `list`
- frozen snapshots/replay: `list`
- wire: whichever you prefer, but keep it consistent and convert automatically at boundaries

------

## A concrete “collapse plan” (low-risk → high-impact)

### Phase 1: No-behavior-change dedupe (fast wins)

- Unify `legacy_protocol.Packet` and `relay_protocol.Packet`
- Unify CLI payload types with driver types (RunResult, BenchmarkAggregate, TelemetryFrame, etc.)
- Unify `_DropdownLayout` base fields into a shared layout struct
- Remove `HudRenderFlags`/`HudRenderContext` duplication by embedding one into the other

### Phase 2: Canonical shared schema modules

Create a `crimson/schema/` or `crimson/wire/` package containing:

- `SessionSettings`
- `SlotState`
- `GameStatus` (the status snapshot)
- `InputBatch` (shared shape)
- `ResyncStream` (begin/chunk/commit shared structs)

Then legacy + relay protocols become *wrappers* (tags + a few extra fields), not independent schema forks.

### Phase 3: Determinism-critical unification

- Move `preserve_bugs`, tick_rate/input_delay, rollback_max_ticks, netcode_mode into `SessionSettings`
- Ensure replay header, net handshake, and sim options derive from the same struct

This is where you eliminate the “it desyncs only on LAN with preserve_bugs toggled” class of issues.

------

## If you want a quick way to *find* duplicates automatically

Even without semantic understanding, you can detect likely duplicates by computing a “schema signature” (field names + annotated types) for every `msgspec.Struct` and grouping identical/near-identical signatures. The CLI-vs-driver payload twins will pop immediately, and you’ll find more you didn’t notice.

you can use ast-grep for seach and large-scale safe codemod.