# Port plan checklist

Use this file as the “source of truth” for what to implement next in `src/` while staying anchored to the decompile. Check items off as they land.

## Milestones

- [ ] 0) Lock authoritative references per mode
- [x] 1) Fix game mode ID consistency (avoid ghosts)
- [x] 2) Extract `BaseGameplayMode` (keep Survival identical)
- [x] 3) Implement Rush (end-to-end)
- [ ] 4) Implement Quests (end-to-end)
- [ ] 5) Implement Tutorial (end-to-end)
- [ ] 6) Implement Typ-o Shooter (end-to-end)
- [ ] 7) Polish + regression tests

---

## 0) Lock down authoritative references per mode

- [ ] Verify/record the exact decompile entrypoints you’re matching (names + addrs)
- [ ] Promote stable names into `analysis/ghidra/maps/name_map.json` (when missing)
- [ ] Re-run headless exports after map changes (prefer `just ghidra-exe`, and `just ghidra-grim` when syncing)

### Quests

- [ ] Start/reset: `quest_start_selected` (`0x0043a790`)
- [ ] Per-frame gameplay + completion transition: `quest_mode_update` (`0x00443d90`)
- [ ] Results screen: `quest_results_screen_update` (`0x00441e20`)
- [ ] Failed screen: `quest_failed_screen_update` (`0x00441820`)
- [ ] HUD bits: confirm where progress ratio + quest title timer are computed in the render path

### Rush

- [ ] Per-frame: `rush_mode_update` (`0x00443fd0`)

### Typ-o Shooter

- [ ] Main per-frame: `survival_gameplay_update_and_render` (state `0x12` branch)
- [ ] Names: `creature_name_assign_random` (`0x004445a0`)
- [ ] Find: `creature_find_by_name` (`0x00444800`)
- [ ] Draw labels: `creature_name_draw_labels` (`0x00444850`)
- [ ] Fire: `player_fire_weapon` (`0x00444980`) (used only by typ-o in the decompile)

### Tutorial

- [ ] Script: `tutorial_timeline_update` (`0x00408990`)
- [ ] Prompt UI: `tutorial_prompt_dialog` (`0x00408780`)

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
  - [x] set player weapon: `QuestDefinition.start_weapon_id`
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
- [ ] Completion detection
  - [x] if no active creatures and spawn table empty: start `completion_transition_ms` if not started
  - [x] after ~1000ms: transition to Quest Results view
- [x] Failure detection
  - [x] if player(s) dead: transition to Quest Failed view (not standard GameOver)

### 4.3 Quest HUD

- [x] show time from `spawn_timeline_ms` (mm:ss)
- [x] progress bar: ratio of kills to estimated total creatures (best-effort; hidden if unknown)
  - [x] estimate total creatures by building spawn plans per `spawn_id`
- [x] quest title fade: show “Quest X-Y” for first few seconds using `quest_name_timer_ms`

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
- [ ] (Optional) animate breakdown like decompile (phase-based count-up)
- [ ] Unlock popups + persistence
  - [ ] if quest grants weapon/perk and it’s newly unlocked: bump `status.weapon_unlock_index` / `status.perk_unlock_index`
  - [ ] show “Weapon unlocked” / “Perk unlocked”
- [ ] Buttons
  - [x] Play Next
  - [x] Play Again
  - [ ] High scores
  - [x] Main menu

### 4.5 Quest Failed screen (`quest_failed_screen_update`)

- [ ] Create a dedicated failed view/UI
- [ ] show “Quest failed” + stats
- [ ] Buttons
  - [ ] Play again (increment `status.quest_fail_retry_count`)
  - [ ] Play another (return to quest selection)
  - [ ] Main menu

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

- [ ] Create `TutorialState`
  - [ ] `stage_index` (0–8)
  - [ ] `stage_timer_ms`
  - [ ] `stage_transition_timer_ms` (negative sentinel + fade controller)
  - [ ] `hint_index`, `hint_alpha`
  - [ ] `repeat_spawn_count`
  - [ ] `hint_bonus_creature_ref` (store creature index, not a pointer)

### 5.2 Port `tutorial_timeline_update` as a pure director

- [ ] Implement `tick_tutorial(dt_ms, tutorial_state, world) -> (ui_model, spawn_actions)`
- [ ] Match stage triggers/behaviors from decompile
  - [ ] Stage 0: after 6000ms → transition
  - [ ] Stage 1: wait for any movement key → spawn XP bonuses
  - [ ] Stage 2: wait until bonuses cleared → transition
  - [ ] Stage 3: wait for fire → spawn small wave (left)
  - [ ] Stage 4: wait until creatures cleared → spawn small wave (right)
  - [ ] Stage 5: powerup lesson loop
    - [ ] spawn “bonus carrier” alien template `0x27` that drops: speed(13), weapon(3 amount 5), double XP(6), nuke(5), reflex boost(9)
    - [ ] spawn supporting enemies to demonstrate the bonus
    - [ ] after enough repeats: force perk lesson (set XP high enough to trigger perk)
  - [ ] Stage 6: wait until perk selection done → spawn larger mixed wave
  - [ ] Stage 7: wait until everything cleared → transition
  - [ ] Stage 8: final message + end buttons
- [ ] Replicate tutorial guardrails
  - [ ] force health to 100 each update
  - [ ] reset XP to 0 outside the perk stage

### 5.3 Implement `tutorial_prompt_dialog`

- [ ] Build a dedicated UI widget (top-of-screen translucent dialog)
- [ ] Fade alpha matches the script’s value
- [ ] Button modes
  - [ ] regular tutorial: “Skip tutorial”
  - [ ] final stage: “Play a game” + “Repeat tutorial”
- [ ] Actions
  - [ ] skip/play → return to menu
  - [ ] repeat → reset tutorial state and clear perks/progression

### 5.4 Tutorial perks special-case

- [ ] In perk generation: if `game_mode_id == 8`, return fixed perk ids (no RNG)

### 5.5 Wiring

- [ ] Add `TutorialMode` + `TutorialGameView`
- [ ] Route `start_tutorial` → `TutorialGameView`

### 5.6 Tests

- [ ] deterministic stage transitions (simulate movement/fire input)
- [ ] deterministic spawns (assert templates/positions for a seeded run)

---

## 6) Typ-o Shooter (names + typing + bespoke spawn/fire)

### 6.1 Creature name table (keep it out of `CreatureState`)

- [ ] Add `CreatureNameTable`
  - [ ] `names: list[str]` sized to creature pool
  - [ ] `assign_random(i, rng, difficulty)` (port decompile incrementally)
  - [ ] `clear(i)` when creature slot becomes inactive
  - [ ] `find_by_name(name) -> index|None` (active creatures only)
- [ ] Initial correctness constraints
  - [ ] enforce uniqueness among active creatures
  - [ ] enforce max length (16)
  - [ ] scale difficulty with XP (decompile changes name generation as XP rises)

### 6.2 Typing buffer + input handling

- [ ] Add `TypingBuffer`
  - [ ] max length 16
  - [ ] gather characters via Raylib `GetCharPressed`
  - [ ] support backspace
  - [ ] on Enter
    - [ ] `shots_fired += 1`
    - [ ] if buffer matches a creature name: `shots_hit += 1`, set `aim_target`, set `fire_requested = True` for this frame
    - [ ] (Optional) handle `"reload"` (decompile checks it)
    - [ ] clear buffer

### 6.3 Firing rules (no “hold mouse button”)

- [ ] Enforce weapon and ammo each frame (infinite ammo)
- [ ] Freeze movement input (always 0)
- [ ] On `fire_requested`: set aim to `aim_target` and fire exactly one shot through normal weapon codepath

### 6.4 Spawn loop (from state `0x12` branch)

- [ ] `spawn_cooldown_ms -= player_count * dt_ms`
- [ ] While `spawn_cooldown_ms < 0`
  - [ ] `spawn_cooldown_ms += 0xDAC - elapsed_ms/800` (clamp min 100)
  - [ ] spawn 2 creatures (right type 4, left type 2) at sine/cos y offsets
  - [ ] set `ai_mode = 8`, set `flags |= 0x80`, set `move_speed *= 1.4`
  - [ ] assign random names to each spawned creature

### 6.5 UI overlays

- [ ] name labels above creatures (`CreatureNameTable.names[i]`)
- [ ] typing input box (bottom-left) with blinking cursor
- [ ] play `typeclick` and `typeenter` sounds

### 6.6 Scoring + highscores

- [ ] `record.game_mode_id = 4`
- [ ] `record.score_xp = player_experience`
- [ ] `record.survival_elapsed_ms = elapsed_ms` (display only)
- [ ] `record.shots_fired` / `record.shots_hit` from typing stats
- [ ] Fix persistence mapping: `scores_path_for_config(mode=4)` → `typo.hi` (avoid `unknown.hi`)

### 6.7 Wiring

- [ ] Add `TypoShooterMode` + `TypoShooterGameView`
- [ ] Route `start_typo` → `TypoShooterGameView`

### 6.8 Tests

- [ ] deterministic name assignment constraints (unique, max len)
- [ ] `find_by_name` correctness
- [ ] spawn loop determinism

---

## 7) Recommended order (minimize rework)

- [x] Mode ID + progression gating cleanup
- [ ] Extract `BaseGameplayMode` (convert Survival, keep identical)
- [x] Rush (end-to-end)
- [ ] Quests gameplay loop (timeline + completion/failure)
- [ ] Quest Results + Failed screens + unlock persistence
- [ ] Tutorial (director + prompt + fixed perks)
- [ ] Typ-o (names + typing + bespoke spawn/fire)
- [ ] Polish + regression tests (mode IDs, perk gating, highscores)
