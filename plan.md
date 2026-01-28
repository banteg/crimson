Below is a concrete, codebase-aware plan that matches how your repo is structured (docs/ for intent, analysis/ for truth, src/ for the port) and keeps fidelity as the guiding constraint.

I’m going to assume the same “view + mode object” pattern you already use for Survival (`SurvivalGameView` → `SurvivalMode` → `GameWorld.update()`), and I’ll call out the key authoritative decompile entrypoints you should mirror for each mode so you always know “what to copy”.

---

## 0) Lock down authoritative references per mode

Before writing new code, pick (and annotate) the exact decompile functions you’re matching so the port doesn’t drift:

### Quests

* **Start/reset**: `quest_start_selected` (addr seen in decompile: `0x0043a790`)
* **Per-frame gameplay + completion transition**: `quest_mode_update` (`0x00443d90`)
* **Post-run screens**:

  * `quest_results_screen_update` (`0x00441e20`)
  * `quest_failed_screen_update` (`0x00441820`)
* **HUD bits**: quest progress bar + quest title fade are embedded in the main gameplay render path; you already found the logic (progress ratio, quest name timer, etc.) in the decompile.

### Rush

* **Per-frame**: `rush_mode_update` (`0x00443fd0`)

### Typ-o-Shooter

Typ-o is *not* a “normal mode update”; it’s mostly in the “typ-o state” variant path:

* **Main per-frame**: `survival_gameplay_update_and_render` (the state `0x12` branch)
* **Supporting functions**:

  * `creature_name_assign_random` (`0x004445a0`)
  * `creature_find_by_name` (`0x00444800`)
  * `creature_name_draw_labels` (`0x00444850`)
  * `player_fire_weapon` (`0x00444980`) (used only by typ-o in the decompile)

### Tutorial

* **Script**: `tutorial_timeline_update` (`0x00408990`)
* **Prompt UI**: `tutorial_prompt_dialog` (`0x00408780`)

This gives you an unambiguous “source of truth” for each subsystem you’ll port.

---

## 1) First: fix game mode ID consistency (or you’ll fight ghosts)

Right now your `src/` has a known mismatch: `GAME_MODE_SURVIVAL = 3` in simulation-land, while the UI/config uses `1` for Survival (and docs map `3` to Quests). That’s going to explode the moment you add Quest/Rush/Typo/Tutorial because:

* perk gating uses `game_mode` numeric checks (`MODE_3_ONLY`, tutorial special cases, rush exclusions)
* highscore sort rules depend on `record.game_mode_id`
* GameOver UI formats score differently based on mode ID

### Do this cleanup before implementing new modes

1. Create a single enum-like source of truth (even if you keep raw ints):

   * `1 = Survival`
   * `2 = Rush`
   * `3 = Quests`
   * `4 = Typ-o`
   * `8 = Tutorial`

2. Update `GameWorld.update()` so it **doesn’t** infer “survival progression enabled” from `game_mode == 3`.

   * Make it explicit: `perk_progression_enabled: bool`, `perk_prompt_enabled: bool`.
   * This is crucial because:

     * Rush: should disable perks entirely (decompile suppresses perk prompt for rush)
     * Quests: likely enables perks (perk prompt excludes only rush)
     * Typ-o: uses different flow (no perk prompt)
     * Tutorial: perks are forced/static only at the perk lesson stage

3. Add a quick regression test (even a tiny one) that asserts:

   * `scores_path_for_config(mode=3)` → `questX_Y.hi`
   * `rank_index(mode=3)` uses ascending time (already implemented)
   * perk generation respects `MODE_3_ONLY` as “mode 3 only” (don’t accidentally “fix” it wrong)

This single step prevents a ton of “why are quests showing survival perks?” debugging later.

---

## 2) Factor a reusable in-game mode “shell” to avoid cloning SurvivalMode 4 times

You’ll implement 4 new modes. If each one duplicates the SurvivalMode loop, you’ll either:

* subtly diverge from original ordering, or
* constantly re-fix bugs in four places.

### Create a `BaseGameplayMode` that owns:

* `GameWorld`
* `elapsed_ms` (and `dt_ms` handling)
* pause/perk-menu gating (`dt=0` behavior)
* screen fade binding (`bind_screen_fade`)
* common “end of run” exit handling (go to menu/restart)

### Subclasses override:

* `prepare_new_run(state)`
  reset world, set terrain, weapon, counters, mode state
* `tick_spawns(dt_ms, state)`
  returns spawns to apply (either `CreatureInit` or “spawn_template calls”)
* `post_world_update(dt_ms, state)`
  completion detection, transitions, special timers
* `render_overlays()`
  quest progress bar, typ-o typing box, tutorial prompts, etc.
* `build_highscore_record()`
  (quests are special: completion time + XP; rush uses time; typ-o uses XP + accuracy)

Do this refactor by first making SurvivalMode subclass the base, keeping it identical.

---

## 3) Rush mode implementation plan

Rush is the best “first new mode” because it’s small and exercises the whole pipeline (spawns → world → game over → highscores).

### 3.1 Mode state

Create a `RushState`:

* `elapsed_ms`
* `spawn_cooldown_ms`

### 3.2 Run start (mirror `rush_mode_update` expectations)

* reset world (like Survival does)
* set/fix weapon and ammo rules:

  * decompile forces weapon id and ammo every frame; you can:

    * set them once at start, and
    * enforce each update to match fidelity (cheap)
* perks:

  * ensure perk prompt/selection is disabled in Rush (decompile does this)

### 3.3 Per-frame loop

After `world.update(...)`:

* call existing `tick_rush_mode_spawns(...)` (already implemented in `creatures/spawn.py`)
* spawn each returned `CreatureInit` with `world.state.creatures.spawn_init(...)`
* increment `elapsed_ms`

### 3.4 HUD + scoring

* HUD: show clock (mm:ss)
* highscore record on death:

  * `record.game_mode_id = 2`
  * `record.survival_elapsed_ms = elapsed_ms`
  * `record.score_xp` optional, but ranking uses time anyway
* ensure `scores_path_for_config()` maps mode 2 → `rush.hi` (it does)

### 3.5 Wiring

* Add `RushGameView` parallel to `SurvivalGameView`
* In `GameLoopView.update()`: route `start_rush` → `RushGameView` (stop using SurvivalGameView as the placeholder)

### 3.6 Tests

* deterministic spawn test:

  * seed RNG
  * call `tick_rush_mode_spawns` for N ticks
  * assert first few spawn positions and template ids match known values

---

## 4) Quests mode implementation plan

Quests are a full “campaign-like” pipeline:

* quest metadata → terrain + start weapon
* timeline spawns + hardcore adjustment
* quest-specific HUD (title fade + progress)
* completion transition
* results screen (time breakdown + unlocks + highscores)
* failed screen

### 4.1 Start-of-run (`quest_start_selected`)

Implement a `QuestMode.prepare_new_run()` that does:

1. **Reset world**:

   * clear creatures/projectiles/bonuses/effects
   * reset player stats (level/xp/perks pending) to match decompile initialization

2. **Terrain**:

   * apply quest’s `terrain_id` and `terrain_over_id`

3. **Player weapon**:

   * set to `QuestDefinition.start_weapon_id`

4. **Spawn table build**:

   * use existing quest builder output (`build_quest_spawn_table(...)`)
   * apply hardcore adjustments exactly like decompile:

     * if hardcore and `count > 1` and spawn_id != `0x3c`:

       * spawn_id == `0x2b` → `count += 2`
       * else → `count += 8`
   * compute and store for HUD:

     * `total_spawn_count = sum(count)`
     * `max_trigger_time_ms = max(trigger_time_ms)`

5. **Timers**:

   * `spawn_timeline_ms = 0`
   * `quest_name_timer_ms = 0` (used for the fade-in quest title overlay)
   * `no_creatures_timer_ms = 0` (for forced-spawn rule)
   * `completion_transition_ms = -1` (negative sentinel like decompile)

6. **Persistence “attempt count”**:

   * increment the “games played” entry for this quest in `status.quest_play_counts`
   * your existing QuestStartView already models indexing (games vs completed offset)

### 4.2 Per-frame quest update (`quest_mode_update`)

After `world.update(...)`:

1. Advance timers:

   * decompile only advances `spawn_timeline_ms` if:

     * there are active creatures OR spawn table not empty
   * always advance `quest_name_timer_ms` while gameplay runs

2. Run spawn timeline:

   * call `tick_quest_mode_spawns(...)` (already exists)
   * apply returned spawn calls via `creature_pool.spawn_template(...)`
   * update and store `no_creatures_timer_ms`

3. Completion detection:

   * if `creatures_none_active` and spawn table empty:

     * start `completion_transition_ms` if not started
     * after ~1000 ms → transition to Quest Results view

4. Failure detection:

   * when player(s) dead → Quest Failed view (separate from standard GameOver)

### 4.3 Quest HUD (from decompile behavior)

Implement a quest HUD overlay:

* **time**: from `spawn_timeline_ms` (mm:ss)
* **progress bar**: ratio of kills to total spawns

  * track:

    * `kills = world.stats.creature_kill_count` (or mirror highscore field)
    * `spawned_count` (increment when you spawn from table)
    * `remaining_count = sum(spawn.count)`
  * `progress = kills / max(spawned+remaining, 1)`
* **quest title fade**: show “Quest X-Y” for first few seconds based on `quest_name_timer_ms`

### 4.4 Quest Results screen (`quest_results_screen_update`)

This needs to be its own view/UI, not `GameOverUi`.

Minimum faithful behaviors to implement:

* compute final time:

  * `base_time_ms = spawn_timeline_ms`
  * `life_bonus_ms = round(p1_health) + round(p2_health if 2p)`
  * `unpicked_perk_bonus_ms = perk_pending_count * 1000`
  * `final_time_ms = base_time_ms - life_bonus_ms - unpicked_perk_bonus_ms`
  * clamp to `>= 1`
* write a highscore record:

  * `game_mode_id = 3`
  * `survival_elapsed_ms = final_time_ms` (quest ranking is ascending time)
  * `score_xp = experience`
* animate the breakdown (optional but doable):

  * count base time up
  * then count bonuses
  * then reveal final time (decompile does this in phases)
* unlock popups:

  * if quest grants weapon/perk *and it’s newly unlocked*, update:

    * `status.weapon_unlock_index`
    * `status.perk_unlock_index`
  * display “Weapon unlocked” / “Perk unlocked”
* buttons:

  * Play Next
  * Play Again
  * High scores
  * Main menu

You can reuse your existing:

* highscore file I/O + rank insertion (`persistence/highscores.py`)
* name entry logic from `ui/game_over.py` (it’s already solid)

### 4.5 Quest Failed screen (`quest_failed_screen_update`)

Implement:

* “Quest failed” title + stats
* buttons:

  * Play again (increment `status.quest_fail_retry_count`)
  * Play another (return to quest selection)
  * main menu

### 4.6 Wiring

* implement `QuestGameView` that reads `state.pending_quest_level`
* in `GameLoopView.update()` route `start_quest` → `QuestGameView`

### 4.7 Tests

* spawn table + hardcore adjustment test (pure)
* completion transition test:

  * force spawn table empty and creatures none → ensure results screen triggers after the right delay
* highscore insertion test for quests (ascending time)

---

## 5) Tutorial mode implementation plan

Tutorial is normal gameplay + a scripted director that:

* advances stage timers
* spawns enemies/bonuses
* forces player health/XP constraints
* draws prompt dialog with “skip” and final buttons

### 5.1 Tutorial state

Create `TutorialState` with:

* `stage_index` (0–8)
* `stage_timer_ms`
* `stage_transition_timer_ms` (negative sentinel + fade controller)
* `hint_index`, `hint_alpha`
* `repeat_spawn_count`
* `hint_bonus_creature_ref` (store creature index, not a pointer)

### 5.2 Port `tutorial_timeline_update` as a pure “director”

Implement a function like:
`tick_tutorial(dt_ms, tutorial_state, world) -> TutorialUiModel + spawn actions`

Match stage behaviors from the decompile:

* Stage 0: after 6000ms → transition
* Stage 1: wait for any movement key → spawn XP bonuses
* Stage 2: wait until bonuses cleared → transition
* Stage 3: wait for fire → spawn small wave left side
* Stage 4: wait until creatures cleared → spawn small wave right side
* Stage 5: powerup lesson loop:

  * spawn “bonus carrier” alien template `0x27` that drops:

    * speed (13)
    * weapon (3, amount 5)
    * double XP (6)
    * nuke (5)
    * reflex boost (9)
  * spawn supporting enemies to demonstrate the bonus
  * after enough repeats → force perk lesson (set XP high enough to trigger perk)
* Stage 6: wait until perk selection done → spawn larger mixed wave
* Stage 7: wait until everything cleared → transition
* Stage 8: final message (“ready to play”) + end buttons

Also replicate tutorial “guardrails”:

* force health to 100 each update
* reset XP to 0 outside the perk stage (like decompile does)

### 5.3 Implement `tutorial_prompt_dialog` UI component

Build a dedicated UI widget:

* top-of-screen translucent dialog box
* fade alpha exactly as the script provides
* two button modes:

  * regular tutorial: “Skip tutorial”
  * final stage: “Play a game” + “Repeat tutorial”
* actions:

  * skip/play → return to menu
  * repeat → reset tutorial state and clear perks/progression

### 5.4 Tutorial perks special-case

Your detangling notes mention Tutorial perks are a fixed list.

Implement in perk generation:

* if `game_mode_id == 8`:

  * return the fixed perk ids (no RNG)

This prevents “tutorial perk lesson” from being random.

### 5.5 Wiring

* Add `TutorialMode` + `TutorialGameView`
* Route `start_tutorial` to it.

### 5.6 Tests

Tutorial is perfect for deterministic tests:

* simulate input events (move/fire)
* assert stage transitions and exact spawn templates/positions

---

## 6) Typ-o-Shooter implementation plan

Typ-o is essentially:

* a typing buffer
* enemies with unique names
* enter-to-attempt-shot
* accuracy counters (shots fired vs hits)
* spawn loop based on elapsed time

### 6.1 Add a separate creature-name table (don’t bloat CreatureState)

Implement a `CreatureNameTable`:

* `names: list[str]` sized to creature pool
* `assign_random(i, rng, difficulty)` (port decompile logic incrementally)
* `clear(i)` when creature slot becomes inactive
* `find_by_name(name) -> index|None` for active creatures

Start with a simplified but deterministic approach, then iterate toward the decompile:

* enforce uniqueness among active creatures
* enforce max length (16)
* scale difficulty with XP (decompile changes name generation as XP rises)

### 6.2 Typing buffer + input handling

Create `TypingBuffer`:

* stores current string (max 16)
* polls char presses (Raylib `GetCharPressed`)
* supports backspace
* on Enter:

  * `shots_fired += 1`
  * if matches a creature name:

    * `shots_hit += 1`
    * set `aim_target` to that creature position
    * set `fire_requested = True` for this frame
  * optionally handle `"reload"` (the decompile checks it)
  * clear buffer

### 6.3 Firing

Do not reuse normal “hold mouse button” logic.

For fidelity and simplicity:

* force weapon each frame (decompile sets weapon_id, ammo constantly)
* ensure “infinite ammo” (reset ammo to clip size or constant)
* freeze movement input (always 0)
* when `fire_requested`:

  * set player aim to `aim_target`
  * fire exactly one shot through your normal weapon firing codepath (one-tick pulse)

### 6.4 Spawn loop

Port the typ-o spawn loop from the state-0x12 decompile branch:

* `spawn_cooldown_ms -= player_count * dt_ms`
* while `< 0`:

  * `spawn_cooldown_ms += 0xDAC - elapsed_ms/800` (clamp min 100)
  * spawn 2 creatures (right type 4, left type 2) at sine/cos y offsets
  * set ai_mode=8, flags|=0x80, move_speed*=1.4
  * assign random names to each spawned creature

### 6.5 UI overlays

Render:

* name labels above creatures (use `CreatureNameTable.names[i]`)
* input box bottom-left showing current typing + blinking cursor
* play “typeclick” and “typeenter” sounds

### 6.6 Scoring + highscores

Typ-o uses XP-based score:

* `record.game_mode_id = 4`
* `record.score_xp = player_experience`
* `record.survival_elapsed_ms = elapsed_ms` (display only)
* `record.shots_fired` / `record.shots_hit` filled from typing stats

You also need to fix persistence:

* extend `scores_path_for_config()` to map mode 4 → `typo.hi`

  * right now typ-o would fall into `unknown.hi`

### 6.7 Wiring

* Add `TypoShooterMode` + `TypoShooterGameView`
* Route `start_typo` to it.

### 6.8 Tests

* deterministic name assignment constraints (unique, max len)
* find_by_name correctness
* spawn loop determinism

---

## 7) Recommended implementation order

This order minimizes risk and reduces rework:

1. **Mode ID + progression gating cleanup** (so you don’t misapply perks/scoring)
2. **Extract BaseGameplayMode** (keep Survival identical, reduce duplication)
3. **Rush** (simple, validates new view wiring and spawn_init path)
4. **Quests gameplay loop** (timeline spawns + completion/failure transitions)
5. **Quest Results + Failed screens + persistence unlocks** (end-to-end quest pipeline)
6. **Tutorial** (scripted director + prompt dialog + fixed perks)
7. **Typ-o** (most bespoke: names + typing UI + unique fire/spawn loops)
8. **Polish + regression tests** (especially around mode IDs and perk gating)

---

If you want a “next action list” to start immediately: do the mode-ID/progression cleanup, then implement Rush end-to-end (new view + mode + spawns + game over + rush.hi). Once that works, you’ll have the skeleton you can clone for Quests/Tutorial/Typ-o with confidence that the plumbing is correct.
