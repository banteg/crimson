# Port plan checklist

Use this file as the “source of truth” for what to implement next in `src/` while staying anchored to the decompile. Check items off as they land.

## Milestones

- [x] 0) Lock authoritative references per mode
- [x] 1) Fix game mode ID consistency (avoid ghosts)
- [x] 2) Extract `BaseGameplayMode` (keep Survival identical)
- [x] 3) Implement Rush (end-to-end)
- [x] 4) Implement Quests (end-to-end)
- [x] 5) Implement Tutorial (end-to-end)
- [x] 6) Implement Typ-o Shooter (end-to-end)
- [x] 7) Polish + regression tests
- [x] 8) Refresh rewrite docs
- [x] 9) High score list screen (state `0xe`)
- [x] 10) High score shot stats (fired/hit)
- [x] 11) High score weapon usage (most used)
- [x] 12) Quest high score stats (shots/weapon usage)
- [ ] 13) Creature ranged attacks (`CreatureFlags.RANGED_ATTACK_*`)
- [ ] 14) Split-on-death (`CreatureFlags.SPLIT_ON_DEATH`)
- [ ] 15) Multiplayer wiring (2–4 players)
- [ ] 16) Demo trial overlay (demo builds)
- [ ] 17) Missing gameplay SFX/events (perk UI, ranged fire, bonus pickup)

---

## 0) Lock down authoritative references per mode

- [x] Verify/record the exact decompile entrypoints you’re matching (names + addrs)
- [x] Promote stable names into `analysis/ghidra/maps/name_map.json` (already present for referenced entrypoints)
- [x] Re-run headless exports after map changes (N/A: no map changes in this milestone)

### Quests

- [x] Start/reset: `quest_start_selected` (`0x0043a790`)
- [x] Per-frame gameplay + completion transition: `quest_mode_update` (`0x004070e0`)
- [x] Results screen: `quest_results_screen_update` (`0x00410d20`)
- [x] Failed screen: `quest_failed_screen_update` (`0x004107e0`)
- [x] HUD bits: confirm where progress ratio + quest title timer are computed in the render path

### Rush

- [x] Per-frame: `rush_mode_update` (`0x004072b0`)

### Typ-o Shooter

- [x] Main per-frame: `survival_gameplay_update_and_render` (`0x004457c0`) (state `0x12` branch)
- [x] Names: `creature_name_assign_random` (`0x00445380`)
- [x] Find: `creature_find_by_name` (`0x00445590`)
- [x] Draw labels: `creature_name_draw_labels` (`0x00445600`)
- [x] Fire: `player_fire_weapon` (`0x00444980`) (used only by typ-o in the decompile)

### Tutorial

- [x] Script: `tutorial_timeline_update` (`0x00408990`)
- [x] Prompt UI: `tutorial_prompt_dialog` (`0x00408530`)

---

## 1) Fix game mode ID consistency (or you’ll fight ghosts)

Goal: eliminate the current “Survival=3” mismatch so perks/highscores/UI don’t silently break as modes are added.

- [x] Create a single enum-like source of truth (even if still stored as ints)
  - [x] `1 = Survival`
  - [x] `2 = Rush`
  - [x] `3 = Quests`
  - [x] `4 = Typ-o`
  - [x] `8 = Tutorial`
- [x] Stop inferring perk progression from `game_mode`
  - [x] Add explicit `perk_progression_enabled: bool` (passed into `GameWorld.update`)
- [x] Add regression tests (tiny is fine)
  - [x] `scores_path_for_config(mode=3)` resolves to `questX_Y.hi`
  - [x] `rank_index(mode=3)` sorts ascending time (quests)
  - [x] `MODE_3_ONLY` behaves as “mode 3 only” (don’t accidentally “fix” it wrong)

---

## 2) Extract `BaseGameplayMode` (to avoid cloning SurvivalMode 4×)

- [x] Introduce `BaseGameplayMode` for shared gameplay plumbing
  - [x] `GameWorld` lifecycle + common asset loading (`open`/`close`)
  - [x] screen fade binding (`bind_screen_fade`) + shared fade draw
  - [x] audio binding/update helper (`bind_audio`, `_update_audio`)
  - [x] UI helpers (`_ui_*`, `_draw_ui_text`, `_update_ui_mouse`)
  - [ ] (Optional) move timekeeping/dt gating into base
- [x] Convert `SurvivalMode` to subclass the base (no behavior changes intended)
- [x] Convert `RushMode` to subclass the base
- [x] Add smoke tests for mode construction

---

## 3) Rush (best first “new mode”)

- [x] Add `RushState`
  - [x] `elapsed_ms`
  - [x] `spawn_cooldown_ms`
- [x] Run start (mirror `rush_mode_update`)
  - [x] reset world
  - [x] enforce weapon + ammo rules (decompile forces each frame; enforce per-update for fidelity)
  - [x] disable perk prompt/selection
- [x] Per-frame loop
  - [x] call `world.update(...)`
  - [x] call `tick_rush_mode_spawns(...)` (already exists in `creatures/spawn.py`)
  - [x] spawn each returned `CreatureInit` via `world.state.creatures.spawn_init(...)`
  - [x] increment `elapsed_ms`
- [x] HUD + scoring
  - [x] show clock (HUD time)
  - [x] record highscores on death: `record.game_mode_id = 2`, `record.survival_elapsed_ms = elapsed_ms`
  - [x] confirm `scores_path_for_config()` maps mode 2 → `rush.hi`
- [x] Wiring
  - [x] add `RushGameView` (parallel to `SurvivalGameView`)
  - [x] route `start_rush` → `RushGameView` in `GameLoopView.update()`
- [x] Tests
  - [x] deterministic spawn test for `tick_rush_mode_spawns` (seed RNG; assert first few templates/positions)

---

## 4) Quests (full pipeline)

### 4.1 Start-of-run (`quest_start_selected`)

- [x] Implement `QuestMode.prepare_new_run()`
  - [x] reset world (clear creatures/projectiles/bonuses/effects)
  - [x] reset player stats to match decompile init (level/xp/perks pending)
  - [x] set terrain: `terrain_id` + `terrain_over_id` from quest metadata
  - [x] set player weapon: `QuestDefinition.start_weapon_id` (native weapon id → runtime id)
  - [x] build spawn table via existing `build_quest_spawn_table(...)`
    - [x] apply hardcore adjustment exactly like decompile
      - [x] only if `hardcore` and `count > 1` and `spawn_id != 0x3c`
      - [x] if `spawn_id == 0x2b` → `count += 2`
      - [x] else → `count += 8`
    - [x] precompute HUD helpers: `total_spawn_count = sum(count)`, `max_trigger_time_ms = max(trigger_time_ms)`
  - [x] init timers/state
    - [x] `spawn_timeline_ms = 0`
    - [x] `quest_name_timer_ms = 0`
    - [x] `no_creatures_timer_ms = 0`
    - [x] `completion_transition_ms = -1` (negative sentinel)
  - [x] increment persistence “attempt count” (`status.quest_play_counts[...]`)

### 4.2 Per-frame quest update (`quest_mode_update`)

- [x] After `world.update(...)`, advance timers
  - [x] advance `spawn_timeline_ms` only if (active creatures) OR (spawn table not empty)
  - [x] always advance `quest_name_timer_ms` while gameplay runs
- [x] Run spawn timeline
  - [x] call `tick_quest_mode_spawns(...)` (already exists)
  - [x] apply spawns via `creature_pool.spawn_template(...)`
  - [x] update `no_creatures_timer_ms` (for forced-spawn rule)
- [x] Completion detection
  - [x] if no active creatures and spawn table empty: start `completion_transition_ms` if not started
  - [x] after ~1000ms: transition to Quest Results view
- [x] Failure detection
  - [x] if player(s) dead: transition to Quest Failed view (not standard GameOver)

### 4.3 Quest HUD

- [x] show time from `spawn_timeline_ms` (mm:ss)
- [x] progress bar: ratio of kills to total quest spawn count (sum of `SpawnEntry.count`)
- [x] quest title fade: show quest title + stage for first ~2s using `quest_name_timer_ms`

### 4.4 Quest Results screen (`quest_results_screen_update`)

- [x] Create a dedicated results view/UI (not `GameOverUi`)
- [x] Compute final time (match decompile)
  - [x] `base_time_ms = spawn_timeline_ms`
  - [x] `life_bonus_ms = round(p1_health) + round(p2_health if 2p)`
  - [x] `unpicked_perk_bonus_ms = perk_pending_count * 1000`
  - [x] `final_time_ms = base_time_ms - life_bonus_ms - unpicked_perk_bonus_ms`
  - [x] clamp `final_time_ms >= 1`
- [x] Write a highscore record (quests sort ascending time)
  - [x] `game_mode_id = 3`
  - [x] `survival_elapsed_ms = final_time_ms`
  - [x] `score_xp = experience`
- [x] Update quest progression persistence
  - [x] increment completion count for stages 1..4 (`status.quest_play_counts[51..90]`)
  - [x] advance quest unlock index (`status.quest_unlock_index` / `status.quest_unlock_index_full`)
- [x] (Optional) animate breakdown like decompile (phase-based count-up)
- [x] Unlock popups
  - [x] show “Weapon unlocked” / “Perk unlocked” from quest metadata
- [x] Buttons
  - [x] Play Next
  - [x] Play Again
  - [x] High scores
  - [x] Main menu

### 4.5 Quest Failed screen (`quest_failed_screen_update`)

- [x] Create a dedicated failed view/UI
- [x] show “Quest failed” + stats
- [x] Buttons
  - [x] Play again
  - [x] Increment `state.quest_fail_retry_count` (matches global `quest_fail_retry_count`)
  - [x] Play another (return to quest selection)
  - [x] Main menu

### 4.6 Wiring

- [x] Implement `QuestGameView` reading `state.pending_quest_level`
- [x] Route `start_quest` → `QuestGameView` in `GameLoopView.update()`

### 4.7 Tests

- [x] spawn table build + hardcore adjustment (pure)
- [x] completion transition delay (~1000ms) when (no creatures) and (table empty)
- [x] quest highscore insertion sorts ascending time

---

## 5) Tutorial (scripted director + prompt dialog)

### 5.1 Tutorial state

- [x] Create `TutorialState`
  - [x] `stage_index` (0–8)
  - [x] `stage_timer_ms`
  - [x] `stage_transition_timer_ms` (negative sentinel + fade controller)
  - [x] `hint_index`, `hint_alpha`
  - [x] `repeat_spawn_count`
  - [x] `hint_bonus_creature_ref` (store creature index, not a pointer)

### 5.2 Port `tutorial_timeline_update` as a pure director

- [x] Implement `tick_tutorial(dt_ms, tutorial_state, world) -> (ui_model, spawn_actions)`
- [x] Match stage triggers/behaviors from decompile
  - [x] Stage 0: after 6000ms → transition
  - [x] Stage 1: wait for any movement key → spawn XP bonuses
  - [x] Stage 2: wait until bonuses cleared → transition
  - [x] Stage 3: wait for fire → spawn small wave (left)
  - [x] Stage 4: wait until creatures cleared → spawn small wave (right)
  - [x] Stage 5: powerup lesson loop
    - [x] spawn “bonus carrier” alien template `0x27` that drops: speed(13), weapon(3 amount 5), double XP(6), nuke(5), reflex boost(9)
    - [x] spawn supporting enemies to demonstrate the bonus
    - [x] after enough repeats: force perk lesson (set XP high enough to trigger perk)
  - [x] Stage 6: wait until perk selection done → spawn larger mixed wave
  - [x] Stage 7: wait until everything cleared → transition
  - [x] Stage 8: final message + end buttons
- [x] Replicate tutorial guardrails
  - [x] force health to 100 each update
  - [x] reset XP to 0 outside the perk stage

### 5.3 Implement `tutorial_prompt_dialog`

- [x] Build a dedicated UI widget (top-of-screen translucent dialog)
- [x] Fade alpha matches the script’s value
- [x] Button modes
  - [x] regular tutorial: “Skip tutorial”
  - [x] final stage: “Play a game” + “Repeat tutorial”
- [x] Actions
  - [x] skip/play → return to menu
  - [x] repeat → reset tutorial state and clear perks/progression

### 5.4 Tutorial perks special-case

- [x] In perk generation: if `game_mode_id == 8`, return fixed perk ids (no RNG)

### 5.5 Wiring

- [x] Add `TutorialMode` + `TutorialGameView`
- [x] Route `start_tutorial` → `TutorialGameView`

### 5.6 Tests

- [x] deterministic stage transitions (simulate movement/fire input)
- [x] deterministic spawns (assert templates/positions for a seeded run)

---

## 6) Typ-o Shooter (names + typing + bespoke spawn/fire)

### 6.1 Creature name table (keep it out of `CreatureState`)

- [x] Add `CreatureNameTable`
  - [x] `names: list[str]` sized to creature pool
  - [x] `assign_random(i, rng, difficulty)` (port decompile incrementally)
  - [x] `clear(i)` when creature slot becomes inactive
  - [x] `find_by_name(name) -> index|None` (active creatures only)
- [x] Initial correctness constraints
  - [x] enforce uniqueness among active creatures
  - [x] enforce max length (16)
  - [x] scale difficulty with XP (decompile changes name generation as XP rises)

### 6.2 Typing buffer + input handling

- [x] Add `TypingBuffer`
  - [x] max length 17
  - [x] gather characters via Raylib `GetCharPressed`
  - [x] support backspace
  - [x] on Enter
    - [x] `shots_fired += 1`
    - [x] if buffer matches a creature name: `shots_hit += 1`, set `aim_target`, set `fire_requested = True` for this frame
    - [x] handle `"reload"` (decompile checks it)
    - [x] clear buffer

### 6.3 Firing rules (no “hold mouse button”)

- [x] Enforce weapon and ammo each frame (infinite ammo)
- [x] Freeze movement input (always 0)
- [x] On `fire_requested`: set aim to `aim_target` and fire exactly one shot through normal weapon codepath

### 6.4 Spawn loop (from state `0x12` branch)

- [x] `spawn_cooldown_ms -= player_count * dt_ms`
- [x] While `spawn_cooldown_ms < 0`
  - [x] `spawn_cooldown_ms += 0xDAC - elapsed_ms/800` (clamp min 100)
  - [x] spawn 2 creatures (right type 4, left type 2) at `y = cos(elapsed_ms*0.001)*256 + world_h*0.5`
  - [x] compute `tint_rgba` from `(elapsed_ms+1)` and pass to spawn
  - [x] apply `creature_spawn_tinted` defaults (ai_mode=2, hp=1, move_speed=1.7, contact_damage=100, heading rand)
  - [x] apply type-specific tweaks (type 4: `flags |= 0x80`, `move_speed *= 1.2`, `size *= 0.8`)
  - [x] assign random names to each spawned creature

### 6.5 UI overlays

- [x] name labels above creatures (`CreatureNameTable.names[i]`)
- [x] typing input box (bottom-left) with blinking cursor
- [x] play `typeclick` and `typeenter` sounds

### 6.6 Scoring + highscores

- [x] `record.game_mode_id = 4`
- [x] `record.score_xp = player_experience`
- [x] `record.survival_elapsed_ms = elapsed_ms` (display only)
- [x] `record.shots_fired` / `record.shots_hit` from typing stats
- [x] Fix persistence mapping: `scores_path_for_config(mode=4)` → `typo.hi` (avoid `unknown.hi`)

### 6.7 Wiring

- [x] Add `TypoShooterMode` + `TypoShooterGameView`
- [x] Route `start_typo` → `TypoShooterGameView`

### 6.8 Tests

- [x] deterministic name assignment constraints (unique, max len)
- [x] `find_by_name` correctness
- [x] spawn loop determinism

---

## 7) Polish + regression tests

### Typ-o Shooter fidelity

- [x] Match native `player_fire_weapon @ 0x00444980` semantics
  - [x] fire is a one-frame pulse (not mouse hold)
  - [x] `shot_cooldown`, `reload_timer`, `spread_heat` reset each frame
  - [x] ammo topped up each frame
- [x] Add regression tests for the above helpers (no Raylib window required)

### Highscores + wiring

- [x] Add a mode-by-mode rank ordering test (Survival/Typ-o by XP desc; Rush by time desc; Quests by time asc)
- [x] Add a smoke test that each `start_*` routes to the intended view (mode id + persistence filename)

---

## Appendix) Recommended order (minimize rework)

- [x] Mode ID + progression gating cleanup
- [x] Extract `BaseGameplayMode` (convert Survival, keep identical)
- [x] Rush (end-to-end)
- [x] Quests gameplay loop (timeline + completion/failure)
- [x] Quest Results + Failed screens + unlock persistence
- [x] Tutorial (director + prompt + fixed perks)
- [x] Typ-o (names + typing + bespoke spawn/fire)
- [x] Polish + regression tests (mode IDs, perk gating, highscores)

---

## 8) Refresh rewrite docs

- [x] Update `docs/rewrite/status.md` to reflect current wiring
- [x] Update `docs/rewrite/index.md` “What exists now” + gaps
- [x] Update `docs/rewrite/tech-tree.md` checkboxes/gaps
- [x] Update `docs/rewrite/game-over.md` parity notes

---

## 9) High score list screen (state `0xe`)

- [x] Add a dedicated high-score list view (local `scores5/*.hi`)
- [x] Allow returning back to Game Over / Quest Results (view stack)
- [x] Wire “High scores” buttons to open the list screen
  - [x] Survival/Rush/Typ-o Game Over
  - [x] Quest Results
- [x] Tests (routing + file selection)

---

## 10) High score shot stats (fired/hit)

- [x] Track `shots_fired` on weapon fire (per-player, per-run)
- [x] Track `shots_hit` on projectile hit (per-player, per-run)
- [x] Populate Survival/Rush high score records with fired/hit counts (clamp `hit <= fired`)
- [x] Tests for fired/hit counters (pure; no Raylib window)

---

## 11) High score weapon usage (most used)

- [x] Track per-weapon usage counts on fire (per-player, per-run)
- [x] Populate Survival/Rush/Typ-o high score records with most-used weapon id (fallback to current weapon)
- [x] Tests for selecting the most-used weapon

---

## 12) Quest high score stats (shots/weapon usage)

- [x] Capture shots fired/hit and most-used weapon at quest end
- [x] Persist shots + most-used weapon into quest high score records (clamp `hit <= fired`)
- [x] Refresh rewrite docs to remove stale high score gaps

---

## 13) Creature ranged attacks (`CreatureFlags.RANGED_ATTACK_*`)

- [ ] Identify ranged attack flags + behavior from the decompile
- [ ] Implement ranged attack fire path (projectiles + cooldowns)
- [ ] Wire the missing SFX/event hooks for ranged fire
- [ ] Add regression tests for ranged attack behavior

---

## 14) Split-on-death (`CreatureFlags.SPLIT_ON_DEATH`)

- [ ] Identify which templates use split-on-death and what they spawn
- [ ] Implement split spawns in the creature death contract
- [ ] Add regression tests for split behavior

---

## 15) Multiplayer wiring (2–4 players)

- [ ] Thread selected player count from the menu into each gameplay mode
- [ ] Support `player_count > 1` in world reset + input plumbing
- [ ] Ensure perks/HUD/high score rules match original for 2p+
- [ ] Add smoke tests for 2p mode startup

---

## 16) Demo trial overlay (demo builds)

- [ ] Implement the demo trial overlay UI + timing rules
- [ ] Confirm trigger conditions vs demo build evidence

---

## 17) Missing gameplay SFX/events (perk UI, ranged fire, bonus pickup)

- [ ] Bonus pickup SFX parity (including variants)
- [ ] Perk UI SFX parity (open/pick/error)
- [ ] Ranged enemy fire SFX parity
