# Refactor attempt

**Status:** Planned (rewrite not started yet as of 2026-01-16)

We want a readable, buildable reconstruction of the engine while keeping a
clear mapping back to the decompiled output. This page summarizes the approach
and where to put work so we can track progress consistently.

## Current state

- `analysis/ghidra/raw/` contains raw Ghidra output and should be treated as
  read-only.
- `rewrite/` is the canonical clean layer where the Zig rewrite lives.
- `third_party/headers/` contains third-party headers (PNG/JPEG/zlib/ogg/vorbis),
  plus DirectX/DirectSound references for later.


## Proposed workflow

1. Start with a narrow subsystem (asset loading, sprite atlas, weapon table).
2. Rename globals/locals in `analysis/ghidra/maps/` as evidence solidifies.
3. Implement the stabilized logic directly in `rewrite/` as idiomatic Zig.
4. Extend `third_party/headers/` as types stabilize so future Ghidra regen
   improves the raw output (codec headers are already imported; DirectX/Win32
   headers will require a fuller Windows header set).
5. Leave short evidence notes near implementations (function addresses, string
   refs, call sites) to keep provenance.


## Success criteria

- The Zig module compiles in isolation with minimal shims.
- Function names and data structures map cleanly to observed runtime behavior.
- The refactor reduces reliance on raw address-based identifiers.


## Risks and constraints

- No debug symbols: most naming must be inferred from behavior.
- Heavy global state: refactoring may require careful initialization ordering.
- Windows-specific APIs: some logic may be thin wrappers around Win32 calls.


## How to track progress

- Update [metrics](metrics.md) after each cleaned module or Ghidra regen.
- Add short notes to the relevant subsystem docs when a behavior is confirmed.
