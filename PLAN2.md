# RNG Trace Unification v1 (`caller_static_u32`-first)

## Summary
- Make the shared `.cdt` RNG contract address-driven and minimal: the canonical per-draw attribution token is the original executable’s `caller_static_u32`.
- Scope this branch to the shared trace schema, Frida finalization, Python replay recording, and the diff/focus consumers. Zig producer changes are explicitly deferred to a follow-up branch.
- Use `.cdt` as the only shared authoritative format. Frida raw JSONL may keep producer-private detail, but no extra shared RNG semantics live only on the Frida side.

## Key Changes
- Bump debug trace schema from `7` to `8` and update the spec/docs accordingly.
- Simplify `RngStreamRow` to:
  - `tick_call_index`
  - `value_15`
  - `state_before_u32`
  - `state_after_u32`
  - `caller_static_u32: int | None`
- Remove `branch_id` from the shared durable schema entirely.
- Keep `caller_static_u32` as an integer on disk; render it as hex only in human-facing output.
- Update Frida finalize so raw `caller_static` hex strings are canonicalized into durable `caller_static_u32` ints when building `.cdt` rows.
- Leave Frida raw capture format private; no raw-format compatibility layer is required beyond what finalize already consumes.

## Python Producer / API
- Change `grim.rand.CrtRand.rand()` to accept explicit per-draw provenance:
  - `rand(*, caller_static_u32: int | None = None) -> int`
- Expand the trace sink contract so Python runtime recording receives `caller_static_u32` with each draw, and `dbg record` writes it into `RngStreamRow`.
- Add strict trace mode for replay/differential recording:
  - when active, any RNG draw emitted during supported gameplay replay recording without `caller_static_u32` fails the trace immediately.
  - this strictness applies to the replay trace path, not to normal gameplay outside debug recording.
- Audit and tag the first-wave gameplay areas in this order:
  - creature spawning
  - effects / FX RNG
  - perks
  - projectiles / weapon fire
  - creature runtime
  - bonuses
- Use original static addresses directly at call sites; do not add a semantic `site_id` layer or resolver registry in this branch.

## Consumer / Tooling Changes
- Update `dbg diff`, `focus`, and RNG comparison helpers to treat `caller_static_u32` as part of the shared RNG row and include it in mismatch details.
- Human-facing reports should print the address in hex form (for example `0x00430b88`) so divergence still maps cleanly to HLIL/decompile work.
- Do not add phase-anchor redesign, resolver tables, or decompile-link generation in this branch; those stay as follow-up work.

## Test Plan
- Unit tests for `CrtRand.rand()`:
  - tagged draw reaches the trace sink with the correct address
  - strict trace mode rejects missing `caller_static_u32`
- Python record tests:
  - recorded `.cdt` rows contain `caller_static_u32`
  - schema v8 trace metadata and channel payloads encode/decode cleanly
- Frida finalize tests:
  - raw hex `caller_static` becomes durable `caller_static_u32`
  - legacy `branch_id` no longer appears in schema v8 rows
- Consumer tests:
  - RNG mismatch detail includes `caller_static_u32`
  - first-mismatch reporting still works with the simplified row shape
- One short replay integration scenario that exercises at least spawn, fire/effects, and perk RNG, and fails if any audited gameplay draw is left untagged.

## Assumptions / Defaults
- No compatibility fallback: schema v8 readers accept v8 only, consistent with current trace-version policy.
- Zig remains on the old producer path for this branch and will need a follow-up branch to emit actual tagged draws instead of reconstructed RNG transitions.
- The root memo and format docs should be updated to reflect the new `caller_static_u32`-first contract and the narrowed branch scope.
