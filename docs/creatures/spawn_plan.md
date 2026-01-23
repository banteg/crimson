---
tags:
  - status-analysis
---

# Spawn plan (pure model of creature_spawn_template)

This repo rewrites `creature_spawn_template` (`crimsonland.exe` 0x00430AF0) as a **pure plan builder**
so we can port templates one-by-one, keep RNG behavior deterministic, and unit test results.

Sources:

- Decompile extracts: `artifacts/creature_spawn_template/`
- Rewrite (current truth): `src/crimson/creatures/spawn.py` (`build_spawn_plan`, `_apply_tail`)

## API

`build_spawn_plan(template_id, pos_xy, heading, rng, env) -> SpawnPlan`

Inputs:

- `template_id`: spawn id used by quest tables and other spawners.
- `pos_xy`: `(x, y)` position.
- `heading`: radians; sentinel `-100.0` means "randomize heading".
- `rng`: MSVCRT-compatible `rand()` stream (`Crand`).
- `env`: `SpawnEnv` (demo/hardcore/difficulty + terrain bounds for the burst effect).

Output (`SpawnPlan`):

- `creatures`: ordered allocations done by the template (base creature is index 0, then any formation children).
- `spawn_slots`: deferred child spawns (spawn-slot configuration); `owner_creature` references `creatures` indices.
- `effects`: side-effects (currently: burst effect).
- `primary`: index of the *returned creature pointer* (the one the shared tail modifies).

Note: `CreatureInit`/`SpawnSlotInit` are intentionally partial views of the original structs; fields not modeled
in the plan are treated as implicit defaults for the purposes of porting.

## Invariants (things that must match the game)

1. Base init is always performed, then template-specific logic mutates it.
2. RNG call order is part of the semantics. Preserve it exactly, including "wasted" calls
   (e.g. the early random heading that gets overwritten by the final `heading` argument).
3. Return pointer semantics matter: templates that allocate extra creatures may return the **last allocated**
   creature, not the base creature. The tail applies to that returned pointer. We model this with `SpawnPlan.primary`.
4. The original uses float32/uint32 fields. In the port we prefer readable float literals (rounding away obvious
   float32 noise), but keep bit-level reinterpretation explicit when it carries semantics (e.g. packed ints).

## Porting workflow (repo conventions)

- Implement the case in `src/crimson/creatures/spawn.py` (`build_spawn_plan`).
- Add the id to `SPAWN_IDS_PORTED` and (once unit-tested) `SPAWN_IDS_VERIFIED`.
- Add/update tests in `tests/test_spawn_plan.py` (RNG consumption is part of the contract).
- Regenerate the spawn-id checklist in `docs/creatures/spawning.md` via `scripts/gen_spawn_templates.py`.

## Example (template 0x12 / ring formation)

Template `0x12` allocates a base creature and then 8 linked children arranged in a ring:

- base creature: stats/tint/size set directly on creature 0
- children: `ai_mode = 3`, link to parent, `target_offset_{x,y} = cos/sin(i * pi/4) * 100`
- return value is the last child (so `primary == 8`), and the tail applies to that child

See the decompile extract (`artifacts/creature_spawn_template/ghidra.c`) and our implementation
(`src/crimson/creatures/spawn.py`) for exact constants and RNG order.
