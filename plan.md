we are working on reimplementing the game in src/, there are docs/ as well as mutliple decompiles (ghidra, ida, binary_ninja) to double-triple check everything. you also have a handy access to binja mcp.

What to document first (to unblock Survival) is anything that defines the “runtime contract” between the already-portable pure models and the missing real-time loop:

## 1) Creature Runtime Contract (must-have)

- [x] Add docs/creatures/update.md (new, status-analysis)
- Goal: a single spec for the minimum subset of creature_update_all we need for Survival.
- Include:
    - [x] Per-tick order: AI target selection (docs/creatures/ai.md + src/crimson/creatures/ai.py), heading/velocity integration, bounds clamp, collision/contact damage, ranged attacks, spawn-slot ticking.
    - [x] "Death contract": when hp crosses <= 0, what gets updated (kill counters, reward_value->XP, bonus drop attempt, fx queues for blood/corpses, SFX).
    - [x] Tables referenced: type table fields (anim rate, base frame, corpse frame, SFX banks) from docs/creatures/animations.md.
    - [x] Spawn-slot semantics (tie to SpawnSlotInit + tick_spawn_slot behavior, currently tested in tests/test_spawn_slots.py but not documented anywhere).

## 2) Survival Mode Contract (must-have)

- [x] Add docs/crimsonland-exe/survival.md (new, status-analysis)
- Goal: define Survival's state + update responsibilities independent of rendering.
- Include:
    - [x] State variables (elapsed_ms, spawn_cooldown, scripted_stage, reward handout gates; see docs/detangling.md + docs/creatures/struct.md).
    - [x] Spawn cadence + milestones as the authoritative model (already in src/crimson/creatures/spawn.py + tests: tests/test_survival_wave.py, tests/test_survival_milestones.py, tests/test_survival_spawn.py).
    - [x] Progression: XP awarding rules (incl. Double XP), level thresholds, perk pending/resolve strategy (we already have survival_progression_update + auto-pick in src/crimson/gameplay.py, but the doc should state what the exe does / what we're approximating).

## 3) Player Damage Contract (must-have for contact damage + "game over")

- [x] Add docs/crimsonland-exe/player-damage.md (new, status-analysis) or extend docs/structs/player.md with a dedicated "player_take_damage" section.
- Include:
    - [x] Shield immunity, reload mitigation, low-health warnings, death timer behavior.
    - [x] Contact damage frequency gate (collision_flag/timer relationship from docs/creatures/struct.md).

## 4) Fix/Restore the Spawn Plan Doc Link (quick win, needed for onboarding)

- [ ] Create docs/creatures/spawn_plan.md (new) OR update references in:
    - docs/creatures/index.md
    - docs/creatures/spawning.md
- [ ] Content: explain build_spawn_plan, what "ported+verified" means, how spawn slots appear in plans, and where the tests live.

## 5) Update Rewrite Status Docs (coordination, not blocking but high leverage)

- [ ] Update docs/rewrite/index.md and docs/rewrite/tech-tree.md to reflect recent reality:
    - SFX, FX pools/queue baking, game.cfg persistence, perk/bonus systems, HUD, console UI, player_update glue.
