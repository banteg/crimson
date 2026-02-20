# Typed Wire + Report Parity Cleanup PRD

## Document Control
- Owner: Crimson rewrite team
- Status: Active
- Last Updated: 2026-02-20
- Tracking Model: Checkbox checklist with acceptance criteria

## Context
We are aligning serialization/reporting code with strict typed-domain rules in `AGENTS.md` and the migration direction agreed in this thread:
1. Keep domain models typed, and avoid dict-building helpers.
2. At IO boundaries, use `msgspec` typed wire schemas and `msgspec.json.encode/decode` directly.
3. If wire keys differ from model keys, align the schema (prefer `version` over `v`) instead of per-field serializer code.
4. If migration is needed, keep it version-gated and isolated, not mixed into normal encode/decode paths.
5. For report scripts, prefer typed payload structs (`msgspec.Struct`) over `asdict`/manual dict assembly.

## Problem Statement
Current code still contains manual dict shaping, reflective dataclass-to-dict conversion, and untyped decode paths in capture/report/CLI tooling. These patterns increase drift risk, hide schema mismatches, and violate fail-fast typed boundaries.

## Goals
- Eliminate untyped dict-building in targeted serialization/reporting paths.
- Make IO contracts explicit via typed `msgspec` schemas.
- Isolate migration logic from default encode/decode runtime paths.
- Preserve deterministic gameplay parity by avoiding behavioral changes in simulation logic.

## Non-Goals
- Rewriting simulation algorithms unrelated to serialization/report output.
- Broad refactors outside listed files unless required for typed schema propagation.
- Cosmetic reformatting-only PRs.

## Success Criteria
- All checklist items below completed with passing verification.
- No remaining `asdict`/`msgspec.to_builtins`/reflective dict-builder usage in targeted files.
- Capture stream and snapshot codecs decode directly into typed schemas.
- Report scripts emit typed payloads encoded directly with `msgspec`.

## Scope and Checklist

### P0: Typed IO Boundaries (Highest Priority)

- [ ] `src/crimson/original/capture.py`: replace untyped stream decode
  - Current risk: `_decode_capture_stream` decodes JSON without `type=` then performs manual branching/conversion.
  - Required change: decode directly into typed stream row schema (`msgspec` union/struct).
  - Acceptance criteria:
    - `msgspec.json.decode(..., type=...)` is used for stream rows.
    - Manual `dict`/`isinstance` row dispatch logic removed or minimized to typed tag routing only.
    - Existing capture round-trip tests pass.

- [ ] `src/crimson/original/capture.py`: replace manual encode row shaping
  - Current risk: `msgspec.to_builtins(...)` plus dict surgery for meta/tick rows.
  - Required change: construct typed wire rows and encode directly.
  - Acceptance criteria:
    - No `msgspec.to_builtins` in capture stream write path.
    - Meta row and tick row serialized from typed structs.
    - Golden/capture output compatibility validated.

- [ ] `src/crimson/net/rollback_snapshot.py`: enforce typed codec schema
  - Current risk: codec may decode untyped payload when `snapshot_type` is omitted.
  - Required change: require explicit schema type for decode (or make untyped mode unreachable in production paths).
  - Acceptance criteria:
    - `Decoder(type=...)` is always used in production code path.
    - Callers provide explicit snapshot schema.
    - Snapshot serialization tests pass.

### P1: Remove Dict-Building from Typed Domain/CLI/Reports

- [ ] `src/crimson/cli.py`: remove reflective `_dc_to_dict` and dict assembly hotspots
  - Current risk: dataclass reflection + `getattr` and manual payload dict composition.
  - Required change: introduce typed payload structs for run/benchmark/report emissions.
  - Acceptance criteria:
    - `_dc_to_dict` removed or no longer used by production output path.
    - `run_result`/benchmark payloads are typed objects encoded via `msgspec`.
    - CLI output snapshots/tests updated and passing.

- [ ] `src/crimson/original/divergence_report.py`: replace `asdict`/`to_builtins` output flattening
  - Current risk: large report payload assembled via ad-hoc dict conversion.
  - Required change: define typed report payload schemas and encode directly.
  - Acceptance criteria:
    - No `asdict`/`msgspec.to_builtins` in final payload assembly path.
    - Report JSON schema remains stable or is version-gated if changed.
    - Existing divergence report tests pass.

- [ ] `src/crimson/original/focus_trace.py`: remove `asdict`-based report serialization
  - Current risk: typed rows flattened into dicts before output.
  - Required change: emit typed report structs.
  - Acceptance criteria:
    - `asdict` removed from trace report output path.
    - Trace report output validated against existing expectations.

- [ ] `src/crimson/original/diagnostics_cache.py` and `src/crimson/original/divergence_bisect.py`: remove `msgspec.to_builtins` output conversion
  - Current risk: typed objects degraded to untyped builtins for JSON/text.
  - Required change: use typed schemas + direct `msgspec` encoding.
  - Acceptance criteria:
    - `msgspec.to_builtins` removed from production serialization path in these files.
    - Existing command/report flows continue to pass tests.

### P2: Report Scripts Use Typed Payload Structs

- [ ] `scripts/gameplay_state_capture_reduce.py`: migrate summary payload to `msgspec.Struct`
  - Current risk: deeply nested manual dict contract with no typed enforcement.
  - Required change: introduce typed summary structs and build output via typed instances.
  - Acceptance criteria:
    - Summary object is typed end-to-end before encoding.
    - Renderer/consumers use typed fields, not dynamic dict traversal.

- [ ] `scripts/panel_state_resolution_capture_reduce.py`: migrate run/overview summary payloads to typed structs
  - Current risk: multiple ad-hoc dict builders for JSON + markdown rendering.
  - Required change: typed models for file summary, run summary, state overview, and top-level summary.
  - Acceptance criteria:
    - Builders return typed objects.
    - JSON emit path uses direct `msgspec` encode.
    - Markdown renderer consumes typed objects.

- [ ] `scripts/quest_build_reduce.py`: migrate row/summary payloads to typed structs
  - Current risk: ad-hoc row and summary dictionaries.
  - Required change: define `QuestBuildRow` and `QuestBuildSummary` (or equivalent typed structs).
  - Acceptance criteria:
    - JSON/CSV emit path built from typed objects.
    - No manual dict row assembly in final output path.

### P3: Schema Key Alignment + Migration Isolation

- [ ] Normalize schema naming to canonical keys (`version`/`schema_version` over `v`)
  - Current risk: drift can reappear in manual dict paths and legacy fixtures.
  - Required change: ensure wire schemas use canonical names, with versioned migration only where required.
  - Acceptance criteria:
    - No new serializer code mapping `v <-> version` per field.
    - Migration logic (if needed) exists in isolated version-gated transform module/path.

- [ ] Validate tooling/tests for legacy key artifacts
  - Current risk: tests may preserve outdated key conventions that conflict with canonical schema.
  - Required change: update ast-grep fixtures/tests where appropriate to reflect enforced canonical contracts.
  - Acceptance criteria:
    - Relevant fixture/test expectations match canonical key policy.
    - `just check` passes.

## Implementation Strategy

### Order of Execution
1. P0 capture and rollback snapshot IO typing.
2. P1 CLI + divergence/focus/diagnostic serialization cleanup.
3. P2 report script typed payload migration.
4. P3 key normalization and migration isolation hardening.

### PR Slicing Plan
- PR A: Capture stream + rollback snapshot typed IO boundary.
- PR B: CLI serialization cleanup (remove reflective dict helpers).
- PR C: Divergence/focus/diagnostic typed report payloads.
- PR D: Script payload struct migrations.
- PR E: Key normalization + fixture/test cleanup.

## Verification Plan
- Run targeted tests after each PR slice.
- Run full repository checks before merge: `just check`.
- For parity-sensitive outputs, compare generated report/capture artifacts against current baselines and ensure differences are intentional.

## Risks and Mitigations
- Risk: schema migration accidentally changes downstream consumer expectations.
  - Mitigation: gate format changes with explicit version fields and isolated migration transforms.
- Risk: broad refactor creates mixed typed/untyped intermediate states.
  - Mitigation: land in small PR slices with strict acceptance criteria and tests.
- Risk: parity regressions from output ordering/representation changes.
  - Mitigation: preserve existing stable ordering and validate against baselines.

## Progress Log
- [ ] Baseline audit captured and checklist approved.
- [ ] PR A merged.
- [ ] PR B merged.
- [ ] PR C merged.
- [ ] PR D merged.
- [ ] PR E merged.
- [ ] Final `just check` pass and docs/status update complete.
