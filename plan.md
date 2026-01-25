# Survival Mode Priorities (Post-Recent Commits)

Last assessed at `HEAD` (commit `43eba52`).

## What Landed Recently (So We Don’t Re-Plan It)

From the recent `git log`:

- `feat(save): implement game.cfg status persistence` (`src/crimson/save_status.py`, wired in `src/crimson/game.py`)
- `feat(fx): implement effects pools and fx queue baking` (`src/crimson/effects.py`, `src/grim/fx_queue.py`, corpse decal baking in `src/grim/terrain_render.py`)
- `feat(gameplay): add player_update runtime glue` (`src/crimson/gameplay.py`, unit tests in `tests/test_player_update.py`)
- `feat(creatures): extract AI targeting logic` (`src/crimson/creatures/ai.py`, tests in `tests/test_creature_ai.py`)
- `feat(audio): add sfx loading and playback` + `refactor(audio): split music and sfx modules` + `feat(sfx): add full sfx key/id map`
  (`src/grim/audio.py`, `src/grim/sfx.py`, `src/grim/sfx_map.py`, `src/crimson/weapon_sfx.py`)

Also already present in-tree (and usable for Survival wiring):

- Survival spawn math + milestone spawns are modeled + tested (`src/crimson/creatures/spawn.py`,
  `tests/test_survival_wave.py`, `tests/test_survival_milestones.py`, `tests/test_survival_spawn.py`)
- Bonus drop/pickup pool is implemented in gameplay state (`src/crimson/gameplay.py:BonusPool`)
- Perk progression + auto-pick is implemented (`src/crimson/gameplay.py:survival_progression_update`)
- HUD overlay renderer exists (`src/crimson/ui/hud.py`) and already draws survival XP/level/progress bars.
- In-game console UI/hotkey is implemented in `src/grim/console.py` and is integrated into the main loop in `src/crimson/game.py`.

## The Actual Blockers for “Playable Survival”

Playable Survival (debug visuals) is now in-tree:

- `uv run crimson game` -> **Play Game** starts Survival.
- `uv run crimson view survival` runs the same loop as a debug view.

Remaining “make it feel like Crimsonland” gaps are tracked in P2/P3 (FX baking, sprite rendering,
SFX, perk selection UI, etc.).

## Priority Plan

### P0 — Fix the Documentation Surface (1 short PR)

Goal: make it easy for multiple people to work without stepping on each other.

- [x] Fix broken/incorrect docs pointers
  - Fixed `docs/creatures/index.md` spawn-plan links (see `docs/creatures/spawn_plan.md`).
- [x] Update rewrite status docs to reflect reality
  - Refreshed `docs/rewrite/index.md` and `docs/rewrite/tech-tree.md`.
- [x] Add a single “Survival wiring” doc stub (even if incomplete)
  - Added `docs/crimsonland-exe/survival.md` (source-of-truth for mode state + update order).

Deliverable: a docs-only change that makes the repo’s current capabilities obvious.

### P1 — Implement Creature Runtime (Core Simulation) (Main Workstream)

Goal: create the minimum faithful creature runtime needed for Survival.

Implement a creature pool module (suggested file: `src/crimson/creatures/runtime.py`).

Must include:

- [x] `CreatureState` runtime struct (Python dataclass) that matches what our systems already expect:
  - required by projectiles: `x`, `y`, `hp`, optional `size`
  - required by AI helper: fields in `CreatureAIStateLike` (`flags`, `ai_mode`, `link_index`, offsets, etc.)
- [x] Pool management
  - fixed-size pool (0x180) to match docs, plus helper to iterate active entries
  - “alloc slot” semantics (reuse oldest/free; doesn’t need perfect parity initially, but must be stable)
- [x] Apply spawn plans into the pool
  - consume `build_spawn_plan(...)` results (creatures + spawn slots + burst effects)
  - remap plan-local indices (`ai_link_parent`, `spawn_slot`) into global pool indices
- [x] Spawn-slot ticking
  - maintain a spawn-slot table and call `tick_spawn_slot` (already exists + tested)
  - on trigger: call `build_spawn_plan(child_template_id, ...)` and spawn children into the pool
- [x] AI movement tick (minimal faithful)
  - call `creature_ai7_tick_link_timer` and `creature_ai_update_target`
  - integrate velocity/position with `move_speed * move_scale`
- [x] Damage + death hooks
  - projectiles already decrement `hp`; creature runtime must:
    - detect death transitions
    - award XP (`award_experience`) using `reward_value` (from spawn templates)
    - attempt bonus drop (`GameplayState.bonus_pool.try_spawn_on_kill`)
    - enqueue FX (blood + rotated corpse) using `FxQueue` / `FxQueueRotated`
    - play SFX (optional in P1, can land in P2) (TODO)
- [x] Player contact damage
  - minimal `player_take_damage` contract: reduces HP unless shield timer > 0, apply any easy perk gates later.
  - tick rate can be approximate for P1; tighten after we have runtime evidence.

Tests to add/extend:

- [x] New tests for spawn-plan -> runtime mapping invariants (formation link indices, spawn slots)
- [x] New tests for “death -> XP award -> bonus spawn attempt” (deterministic RNG)

### P2 — Build a Survival Gameplay View/Loop (Wiring + Rendering)

Goal: make Survival selectable from the menu and actually run.

- [x] Add a new view (suggested: `src/crimson/views/survival.py`) that owns:
  - `GameplayState` (player/projectiles/bonuses/perks)
  - players list (`PlayerState`)
  - creature runtime pool (P1)
  - survival mode state: `elapsed_ms`, `spawn_cooldown`, `scripted_stage`
- [ ] Tick order (first pass; match docs later)
  - player input -> `player_update`
  - projectile updates vs creatures
  - creature updates vs players
  - bonus pool update + pickups
  - progression update (`survival_progression_update`, likely `auto_pick=True` initially)
  - FX queue baking into ground (`grim.fx_queue.bake_fx_queues`)
- [ ] Rendering (ship in stages)
  - [x] P2a: debug shapes for creatures/projectiles/bonuses so the loop is testable immediately
  - [ ] P2b: sprite rendering using existing atlas helpers + creature_anim functions + `projs.png` mapping
  - [x] HUD overlay via `src/crimson/ui/hud.py` (already implemented)
- [x] Wire “Play Game” menu action to start Survival view instead of the placeholder panel.

### P3 — Parity Polish (After Survival Is Playable)

These can be parallelized once P1/P2 are in place:

- [ ] Tighten contact damage timing + shields/reload mitigation against docs/runtime captures.
- [ ] Implement perk prompt UI (or at least a “press key to pick perk” overlay) instead of auto-pick.
- [ ] SFX integration for the runtime loop:
  - weapon fire/reload (reuse `resolve_weapon_sfx_ref`)
  - creature pain/death SFX banks (from `docs/creatures/animations.md` type table)
  - bonus pickup SFX
- [ ] Implement remaining bonus behaviors needed for Survival feel (nuke, shock chain, freeze affecting AI, etc.).
- [ ] Replace any remaining DemoView-only simulation pieces by reusing the real Survival systems.

## Suggested Work Split (So We Don’t Block Each Other)

- **Docs owner**
  - P0 fixes + write `docs/crimsonland-exe/survival.md` and a short `docs/creatures/runtime.md` describing the P1 runtime contract.
- **Creature runtime owner**
  - P1 (`src/crimson/creatures/runtime.py`) + tests.
- **Gameplay loop/rendering owner**
  - P2 (`src/crimson/views/survival.py`) + minimal rendering + menu wiring.
- **Evidence owner (windows-vm)**
  - Capture contact-damage tick rate, reward_value->XP mapping, and any survival gating oddities; feed back into docs + tweaks.
