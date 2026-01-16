# Refactor attempt

**Status:** Planned (no clean sources yet as of 2026-01-16)

We want a readable, buildable reconstruction of the engine while keeping a
clear mapping back to the decompiled output. This page summarizes the approach
and where to put work so we can track progress consistently.

## Current state

- `source/decompiled/` contains raw Ghidra output and should be treated as
  read-only.
- `source/clean/` is where cleaned C should live (currently empty).
- `source/headers/` is reserved for third-party headers used by the Ghidra
  C parser (currently empty).

## Proposed workflow

1. Start with a narrow subsystem (asset loading, sprite atlas, weapon table).
2. Copy only the relevant functions into `source/clean/` and refactor them in
   place.
3. Rename globals/locals and introduce small structs and enums as they become
   clear.
4. Add header files in `source/headers/` once types stabilize so future Ghidra
   regen improves the raw output.
5. Leave short evidence notes near refactors (function addresses, string refs,
   call sites) to keep provenance.

## Success criteria

- The cleaned module compiles in isolation with minimal shims.
- Function names and data structures map cleanly to observed runtime behavior.
- The refactor reduces reliance on raw address-based identifiers.

## Risks and constraints

- No debug symbols: most naming must be inferred from behavior.
- Heavy global state: refactoring may require careful initialization ordering.
- Windows-specific APIs: some logic may be thin wrappers around Win32 calls.

## How to track progress

- Update `docs/metrics.md` after each cleaned module or Ghidra regen.
- Add short notes to the relevant subsystem docs when a behavior is confirmed.
