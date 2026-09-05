---
tags:
  - reverse-engineering
  - static-analysis
---

# Source recovery references

Function and data recovery is recorded by native address. The old aggregate
naming notebook duplicated format, struct and behavior pages and retained
superseded hypotheses. Its unique observations are preserved in the
[historical notebook](https://github.com/banteg/crimson/blob/master/analysis/archive/2026-09-05-detangling.md);
it is not a maintained reference or a backlog.

## Resolve current evidence

```bash
just analysis-function creature_handle_death
uv run crimson match status
```

- `analysis/ghidra/maps/name_map.json` and `analysis/ghidra/maps/data_map.json`
  record canonical names, signatures and data labels.
- `analysis/annotations/functions.json` retains address-keyed recovery notes.
- `tools/match/STATUS.md` reports matching results; each scratch's configuration
  identifies its source, including bodies moved into `tools/native/recovered/`.
- [Binary analysis](binary-analysis.md) describes current source/view lookup.
- [Native linking](native-linking.md) distinguishes recovered code, library
  providers, linkability and byte-match evidence.

## Behavior and layout references

- [Config blob](../../formats/crimson-cfg.md) and [save/status](../../formats/save-status-format.md).
- [Player](../../structs/player.md), [creatures](../../creatures/struct.md),
  [projectiles](../../structs/projectile.md), and [effects](../../structs/effects.md).
- [Gameplay](../../crimsonland-exe/gameplay.md), [Survival](../../crimsonland-exe/survival.md),
  [UI](../../crimsonland-exe/ui.md), and [online scores](../../crimsonland-exe/online-scores.md).
- [Perk call sites](perks-runtime-reference.md) and [mechanics](../../mechanics/perks.md).
- [Grim API](../../grim2d/api.md) and its [evidence appendix](../../grim2d/api-evidence.md).

Keep new findings in the owning reference page after verification. A recovered
name is not by itself proof of behavior; retain instruction addresses, capture
provenance and remaining uncertainty where they affect the conclusion.
