# Panel State Resolution Capture Interpretation (2026-02-16)

## Scope

This memo interprets the latest complete `panel_state_resolution_capture_*.jsonl`
artifacts in:

- `artifacts/frida/share/`

Focus: whether panel-state sweep captures are now reliable across resolutions,
including hover-dependent right-panel content in states `14/15/16`.

## Inputs Used

Latest complete capture per resolution:

- `artifacts/frida/share/panel_state_resolution_capture_640x480_20260216_091919_9b09a93f.jsonl`
- `artifacts/frida/share/panel_state_resolution_capture_800x600_20260216_092012_8657473c.jsonl`
- `artifacts/frida/share/panel_state_resolution_capture_960x600_20260216_092106_ccd0f00a.jsonl`
- `artifacts/frida/share/panel_state_resolution_capture_1024x768_20260216_093101_eff27bf4.jsonl`

## Summary

All four resolutions now produce complete sweeps:

- `18/18` `state_result` rows
- all `state_result.result == "captured"`
- zero zero-signal captured states
- valid `sweep_done` row present
- no JSON parse errors at EOF

## Resolution Results

| Resolution | Run ID | Lines | Sweep Status | State Coverage | Right-panel marker hits (14/15/16) |
| --- | --- | ---: | --- | --- | ---: |
| `640x480` | `20260216_091919_9b09a93f` | `2438` | complete | `18/18 captured` | `15 / 13 / 5` |
| `800x600` | `20260216_092012_8657473c` | `2391` | complete | `18/18 captured` | `15 / 17 / 6` |
| `960x600` | `20260216_092106_ccd0f00a` | `2377` | complete | `18/18 captured` | `12 / 11 / 3` |
| `1024x768` | `20260216_093101_eff27bf4` | `2324` | complete | `18/18 captured` | `17 / 20 / 6` |

Marker-hit counts above are from right-panel-specific text signatures:

- state `14` (high scores): `Local score`, `Rank:`, `Frags`, `Hit %`, `Show internet scores`, `Selected score list`, `Game mode`, etc.
- state `15` (weapons DB): `Firerate`, `Reload time`, `Clip size`, `wepno #*`, etc.
- state `16` (perks DB): `perkno #*`, `Why kill for experience...`, etc.

## Hover Capture Interpretation

For all four complete runs:

- state `14` logs `capture_hover_plan` with `source=fallback+ui_bounds`, `point_count=7`, and `capture_hover_step=6`
- states `15` and `16` log `source=fallback+ui_bounds`, `point_count=6`, and `capture_hover_step=6`

Interpretation:

- hover sampling is no longer single-point only
- left-list hover progression is happening during dwell
- right-panel variant text is now captured in all target resolutions

## What This Means

The two previously observed failure modes are resolved in the current captures:

1. Early sweep-start timing issue (launcher/boot race): no longer causing zero-signal early states.
2. Missing hover-dependent right-panel content in `14/15/16`: now present through multi-point hover plans.

Remaining variation in marker-hit counts across resolutions appears content-driven
(saved-score/unlock list differences), not a capture-mechanics failure.

## Recommended Baseline Set

Use these run IDs as current “known-good” panel sweep references:

- `20260216_091919_9b09a93f` (`640x480`)
- `20260216_092012_8657473c` (`800x600`)
- `20260216_092106_ccd0f00a` (`960x600`)
- `20260216_093101_eff27bf4` (`1024x768`)
