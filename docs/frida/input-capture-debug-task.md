---
tags:
  - task
  - frida
  - windbg
  - input
---

# Task: Debug Missing Input Capture in `gameplay_diff_capture.js`

## Problem
Recent capture (`artifacts/frida/share/gameplay_diff_capture.json.gz`) resolves and hooks input helpers successfully:

- `input_any_key_pressed` (`0x00446000`)
- `input_primary_just_pressed` (`0x00446030`)
- `input_primary_is_down` (`0x004460f0`)

…but tick telemetry shows zero input query calls and zero true hits across ~60k ticks.

This likely means the gameplay path for this run is not using those wrappers (or we’re observing the wrong callsite/runtime path).

## Goal
Identify the real input query path used during gameplay and update
`scripts/frida/gameplay_diff_capture.js` so input capture produces non-zero,
actionable telemetry during normal play.

## Constraints
- Keep capture overhead practical for long sessions.
- Preserve deterministic tick alignment and existing output schema.
- Backtrace should stay optional/off by default.

## Evidence to Start From
- Capture file: `artifacts/frida/share/gameplay_diff_capture.json.gz`
- Summary: `analysis/frida/original_capture_summary.json`
- Script: `scripts/frida/gameplay_diff_capture.js`
- Input decompile references:
  - `analysis/ida/raw/crimsonland.exe/crimsonland.exe_decompiled.c`
  - `docs/detangling.md` (input sections)

## Suggested Debug Plan

1. Confirm live execution of known wrappers in debugger.
2. If wrappers are cold, identify hot lower-level input functions (grim vtable path).
3. Hook the true hot functions in Frida with compact counters.
4. Re-run a short interactive capture and verify non-zero input telemetry.
5. Update script + docs.

## WinDbg / CDB Steps (Windows)

### A) Attach and breakpoints
Use one of:

```text
just windbg-client
```

or directly:

```text
cdb -pn crimsonland.exe
```

Set breakpoints:

```text
bp 00446000 ".echo HIT input_any_key_pressed; kb; g"
bp 00446030 ".echo HIT input_primary_just_pressed; kb; g"
bp 004460f0 ".echo HIT input_primary_is_down; kb; g"
```

Exercise gameplay input (move/fire/reload/menu).

### B) If no hits, break on Grim input query path
From decompile, likely grim query route is vtable-backed. Break on candidate Grim methods if symbols/addresses are known in your session, or break on callsites that invoke vtable `+0x80` and `+0x58` from gameplay hot paths.

Useful strategy:

- Break in `gameplay_update_and_render` (`0x0040aab0`)
- Step/trace call instructions related to input polling
- Record concrete callee addresses used each frame when moving/firing

### C) Confirm active hot function(s)
For each candidate, collect:

- call count over ~10 seconds
- whether it correlates with key/mouse actions
- return value semantics

## Frida Script Update Requirements

Update `scripts/frida/gameplay_diff_capture.js` to:

1. Hook the proven hot input function(s) (not just the wrappers if wrappers are cold).
2. Emit per-tick compact stats compatible with existing fields:
   - `input_queries.stats.*`
   - `event_counts.input_*`
3. Keep raw event diagnostics gated by `CRIMSON_FRIDA_INCLUDE_RAW_EVENTS`.
4. Add env knobs only if necessary; defaults should “just work”.

## Verification Checklist

Run a short interactive session (movement + firing + menu transitions) and verify:

- `event_counts.input_primary_edge` non-zero for click/press actions
- `input_queries.stats.primary_down.calls` non-zero during active gameplay
- `input_true_total` in summary non-zero for at least one input class
- no script syntax errors (`node --check`)

## Deliverables

1. Script patch to `scripts/frida/gameplay_diff_capture.js`
2. Doc update in `docs/frida/gameplay-diff-capture.md` if hook source changes
3. Short findings note (append to this file or add sibling note) with:
   - root cause
   - final hooked function(s)
   - before/after telemetry stats from a short run

## Definition of Done

A fresh short capture from real gameplay includes non-zero input telemetry in tick rows,
with stable performance and no regressions in existing checkpoint conversion.
