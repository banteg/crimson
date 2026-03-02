# Schema Consolidation Plan (Tightened)

## Objective
Reduce schema drift across net/replay/debug/CLI without breaking wire compatibility or replay determinism.

## Scope
- In scope: `msgspec.Struct` duplication, boundary model drift, conversion glue complexity.
- Out of scope (for now): changing gameplay behavior, changing protocol tags on the wire, changing replay format unless explicitly versioned.

## Key Principles
1. One canonical internal model per concept.
2. Versioned boundary models at compatibility edges (net/replay/CLI).
3. No implicit shape changes: every boundary change gets tests and explicit migration.
4. Prefer additive refactors first; destructive removals only after callsites are migrated.

## Hotspots (Validated)

### 1) Net protocol split-brain (lockstep vs relay)
- Real overlap exists, but not all pairs are 1:1.
- Exact/shared candidates:
  - `lockstep_protocol.LobbySlot` and `relay_protocol.RelaySlot`
  - Packet envelope header (`seq`, `ack`, `reliable`)
- Near-duplicate (needs adapters, not immediate merge):
  - lockstep: `Hello/Welcome/MatchStart`
  - relay: `ClientHello/ClientWelcome/RoomCreate/RoomState/RoomStart`
- Resync models are semantically similar but structurally different; treat as boundary versions.

### 2) Status snapshot drift (net/replay/debug/persistence)
- Current split across:
  - `lockstep_protocol.StatusSnapshot`
  - `replay.types.ReplayStatusSnapshot`
  - `dbg.canonical_channels.SnapshotStatus`
  - persistence blob schema (`save_status.GAME_STATUS_STRUCT`)
- Field overlap is partial and container choices differ (`list` vs `tuple`).

### 3) CLI payload twins vs driver structs
- Many `_...Payload` structs mirror driver structs with small differences.
- This is a maintainability hotspot, but not always no-op to merge because CLI includes extra formatted fields (`elapsed_s`) and different collection shapes.

### 4) UI schema duplication
- `HudRenderFlags` and duplicated booleans in `HudRenderContext`.
- `_DropdownLayout` duplicated in two modules with overlapping base fields.

### 5) Owner identity model split
- Runtime model uses `OwnerRef` heavily.
- Some replay/debug snapshots still emit legacy `owner_id: int`.

## Execution Plan

### Phase 0: Safety Rails (required before dedupe)
1. Add characterization tests for current boundary contracts:
   - Net encode/decode roundtrip for lockstep + relay packets.
   - Replay header and status encode/decode roundtrip.
   - CLI JSON snapshot tests for replay/info/benchmark commands.
2. Add schema inventory script (AST-based) to compute signatures for all `msgspec.Struct` classes.

Exit criteria:
- Baseline snapshots committed.
- Any future shape drift fails tests.

### Phase 1: Truly low-risk dedupe
1. Introduce `PacketHeader` shared struct (`seq`, `ack`, `reliable`) and compose in both protocol packet types.
2. Introduce shared `SlotState` and alias/adapt in both lockstep and relay.
3. Extract shared `DropdownLayoutBase` and keep module-specific extension fields local.
4. Resolve HUD duplication with a transitional shape:
   - Add `flags: HudRenderFlags` to `HudRenderContext`.
   - Keep old boolean kwargs temporarily.
   - Migrate callsites, then remove duplicated booleans.

Exit criteria:
- No wire/replay/CLI output changes.
- Net + UI tests pass unchanged.

### Phase 2: Canonical status model with adapters
1. Introduce canonical internal status type (name to avoid collision with persistence `GameStatus`, e.g. `ProgressStatusSnapshot`).
2. Add explicit adapters:
   - persistence blob <-> canonical
   - lockstep status wire <-> canonical
   - replay status <-> canonical
   - debug status <-> canonical
3. Keep boundary-specific containers if needed, but centralize conversion in one adapter module.

Exit criteria:
- One canonical internal status source.
- Determinism tests unchanged.
- Replay compatibility preserved (no format bump yet).

### Phase 3: Session settings unification
1. Introduce canonical `SessionSettings` (mode/player_count/tick/input delay/preserve_bugs/netcode/rollback/quest_level).
2. Add adapters for:
   - lockstep handshake/start messages
   - relay create/state/start messages
   - replay header fields used by playback config
3. Keep existing wire message shapes and tags; only internal derivation is unified.

Exit criteria:
- `preserve_bugs` and timing/network settings derive from one canonical object internally.
- No protocol wire incompatibility introduced.

### Phase 4: CLI payload rationalization
1. Separate concern clearly:
   - internal result structs (driver)
   - public CLI JSON schemas (versioned contract)
2. Replace mirrored struct definitions where shape is identical.
3. For non-identical shapes, keep explicit serializer functions (no duplicated domain structs).

Exit criteria:
- CLI schema versions remain explicit.
- Snapshot tests prove no accidental output breakage.

## Compatibility Rules
1. Net:
   - Do not change msg tags or required fields without a protocol version bump + negotiation.
2. Replay:
   - Any structural replay header/input change requires replay format version bump and migration notes.
3. CLI JSON:
   - Treat as public contract; changes require schema version bump and changelog entry.

## Validation Matrix
- Unit tests:
  - Adapter roundtrips for status/session models.
  - Legacy owner id <-> `OwnerRef` conversion invariants.
- Integration tests:
  - LAN lockstep join/start with `preserve_bugs=true/false`.
  - Relay room create/join/start with rollback settings.
- Determinism checks:
  - Replay verify and checkpoint diff on fixed seeds.
- Golden outputs:
  - `cli replay verify/info/benchmark` JSON snapshots.

## Suggested Work Order (PR slices)
1. PR1: Phase 0 rails + schema inventory tool.
2. PR2: Phase 1 low-risk dedupe (`PacketHeader`, `SlotState`, layouts, HUD transition).
3. PR3: Phase 2 status canonicalization + adapters.
4. PR4: Phase 3 session settings canonicalization + adapters.
5. PR5: Phase 4 CLI payload cleanup + serializer consolidation.

## Notes
- Use `ast-grep` (`sg`) for discovery and codemod candidates, but keep codemods gated by tests.
- Prefer mechanical refactors first; behavior changes require isolated PRs.
