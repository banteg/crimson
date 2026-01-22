---
tags:
  - status-tracking
---

# Progress metrics (goal-oriented)

**Status:** Tracking

This page tracks progress toward two goals:

1) Evidence-backed understanding of the original game.
2) An idiomatic rewrite with known behavior parity.

## How to update

- Update after a Ghidra regen, runtime capture, or rewrite milestone.
- Prefer evidence-linked notes over raw percentages.

## Subsystem status (primary dashboard)

Legend:
- **Understanding:** draft / in-progress / validated / mixed
- **Evidence:** static / runtime / both / format
- **Rewrite:** spec / prototype / parity / tested / TBD

| Subsystem | Understanding | Evidence | Rewrite | Notes |
| --- | --- | --- | --- | --- |
| Boot & startup | in-progress | both | TBD | entrypoint.md, boot-sequence.md |
| Formats (PAQ/JAZ/Fonts) | mixed | format | spec | formats/*.md |
| Asset pipeline | in-progress | static | TBD | pipeline.md |
| Grim2D | draft | runtime | TBD | grim2d-overview.md, grim2d-runtime-validation.md |
| Weapons / perks / bonuses | in-progress | both | TBD | weapon-table.md, perk-id-map.md, bonus-id-map.md |
| Quests | validated | runtime | spec | quest-builders.md |
| UI & menus | draft | static | TBD | crimsonland-exe/ui.md, ui-elements.md |
| Audio / SFX | in-progress | static | TBD | sfx-id-map.md, sfx-usage.md, audio-entry.md |
| Save / config | draft | static | TBD | save-status-format.md, crimson-cfg.md |
| Secrets / minigames | draft | runtime | TBD | secrets.md |

## Evidence pipeline (per cycle)

| Metric | Current | Source |
| --- | --- | --- |
| New runtime captures | TBD | analysis/frida/raw/, artifacts/frida/share/ |
| Facts promoted into maps | TBD | analysis/ghidra/maps/* (git diff) |
| Docs updated with evidence links | TBD | docs/ |
| Top unknowns reduced | TBD | docs/detangling.md, docs/work-status.md |

## Rewrite readiness (specs + tests)

| Spec | Status | Tests | Parity | Notes |
| --- | --- | --- | --- | --- |
| PAQ reader | spec | TBD | TBD | formats/paq.md |
| JAZ decode | spec | TBD | TBD | formats/jaz.md |
| Fonts | draft | TBD | TBD | formats/fonts.md |
| Weapon table | in-progress | TBD | TBD | weapon-table.md |
| Quest builders | validated | TBD | TBD | quest-builders.md |
| Save/status | draft | TBD | TBD | save-status-format.md |
| Config blob | draft | TBD | TBD | crimson-cfg.md |

## Known behavior deltas (rewrite vs original)

- None recorded yet. Add entries here when the rewrite intentionally diverges.
