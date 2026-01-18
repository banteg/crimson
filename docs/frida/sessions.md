# Frida sessions

Use this format to capture what we wanted, what actually happened, and what we learned.

## Session template

- **Date:**
- **Build / platform:**
- **Scripts:** `grim_hooks.js`, `crimsonland_probe.js`
- **Attach method:** `frida -n crimsonland.exe -l Z:\...`
- **Artifacts:** JSONL logs + reducer outputs

### Wants (pre-run)

Describe the goals and the exact in-game actions to trigger.

### Run summary (actual)

Timeline of what happened and when (relative timestamps are fine).

### Findings

- Evidence-backed observations (struct offsets, timers, UI calls, etc).
- Cite log snippets or reducer outputs.

### Actionable insights

- What to rename/type in Ghidra.
- Which offsets need MemoryAccessMonitor follow-ups.
- What to change in hooks for the next run.

---

# session 1

## session wants

Here’s a short session I’d love recorded to nail down unknown player‑struct offsets + HUD/bonus timers (the stuff the unknown‑field tracker will surface):

  Goal: correlate unknown player offsets with concrete gameplay events (damage, shield, slow‑time, freeze, power‑ups, perk selection, game‑over UI).

  Session (5–8 min, Survival mode, single‑player):

  1. Start Survival and enter gameplay. In Frida REPL run: dumpPlayer(0).
  2. Shoot + reload a few times. Take damage until HP drops below ~20 to trigger low‑health behavior/blood bursts.
  3. Pick up as many bonus types as you can find (Reflex/slow‑time, Freeze, Weapon Power‑Up, Double XP, Shield/armor).
     After each pickup, run dumpPlayer(0) again.
  4. Trigger a perk selection screen (level up). As it appears, run: startHotWindow(2000) to capture UI draw calls. Then pick a perk.
  5. Die to reach game‑over/high‑score entry; when the screen appears, run startHotWindow(2000) again. Type a name, view High Scores, return to menu.

  Optional (super useful if you have time):

  - Watch the player_unknown_tracker_report lines; if one offset spikes, do:
      - watchPlayerOffset(0, 0x????, 4) → repeat the in‑game action that triggered it → stopWatchPlayerOffset().

  This should give me enough runtime evidence to map timers/flags that still aren’t labeled and to confirm which HUD/UI elements flip which fields.

## rough session description

Based on the video provided, here is the timeline of events.

**Note:** As requested, **00:00** corresponds to **00:11** in the video player (the moment the "Play" button was clicked in the launcher).

**Startup & Initialization**
*   **00:00** – Launcher "Play" button clicked.
*   **00:26** – Main Menu appears.
*   **00:30** – User selects "Play Game" -> "Survival".
*   **00:33** – **Gameplay begins.**

**Session Part 1: Baseline & Damage**
*   **00:35** – Player fires weapon and reloads (Step 2).
*   **00:40** – **Frida Command:** `dumpPlayer(0)` (Baseline state).
*   **00:57** – Player takes significant damage (HP turns red).
*   **01:03** – **Frida Command:** `dumpPlayer(0)` (Capturing low health state).

**Session Part 2: Power-ups**
*   **01:19** – Player picks up **"Freeze"** bonus.
*   **01:21** – **Frida Command:** `dumpPlayer(0)` (Capturing Freeze flag/timer).
*   **01:24** – Player picks up **"Fire Bullets"** bonus.
*   **01:26** – **Frida Command:** `dumpPlayer(0)` (Capturing Fire Bullets flag/timer).

**Session Part 3: Perk UI Analysis**
*   **01:35** – Player levels up; "PICK A PERK" screen appears.
*   **01:37** – **Frida Command:** `startHotWindow(2000)` (Capturing UI draw calls for the perk window).
*   **01:42** – Player selects the "Telekinetic" perk.

**Session Part 4: Speed Bonus**
*   **02:11** – Player picks up **"Speed"** bonus.
*   **02:13** – **Frida Command:** `dumpPlayer(0)` (Capturing Speed flag/timer).

**Session Part 5: Game Over & High Score UI**
*   **02:23** – Player dies; "THE REAPER GOT YOU" screen appears.
*   **02:27** – **Frida Command:** `startHotWindow(2000)` (Capturing UI draw calls for the high score entry).
*   **02:28** – User enters name "banteg" into the high score field.
*   **02:33** – High Scores list displayed.
*   **02:37** – User returns to Main Menu.
*   **02:40** – User quits the game.
*   **02:42** – **Frida Command:** `exit`.

## findings

- Auto-record triggers fired; counts: startup (1), low_health (1), bonus_apply (4), perk_apply (1),
  perk_selection_screen (6), game_over_screen (10). Low-health dump shows HP crossing ~24.19 → 18.67.
- Unknown-field tracker still only reported offsets `0x2BC`, `0x2C4`, `0x2D0`, `0x34C`, `0x350`, `0x354`
  with count=1 each, so no clear “hot” offset yet.
- Texture name decoding remains unreliable: `texture_get_or_load` names are mostly null or long garbage blobs
  (string-table dumps), implying the arg is not a direct `char *` for these callsites.
- Disassembly shows `texture_get_or_load` / `_alt` take **two args** (name + path). Callers push both.
  We were only logging arg0; update the probe to log both and prefer the path string.
- Grim vtable evidence aligns with render-heavy paths (`ui_element_render`, `ui_render_hud`, `projectile_render`,
  `creature_render_type`, `bonus_render`), confirming coverage but not yielding new renames.
- SFX evidence is still sparse; sfx 63 appears in `ui_button_update`/`ui_menu_item_update` and perk UI, likely
  a UI click/confirm.

## actionable insights

- Raise `autoRecord.dumpCooldownMs` / `hotWindowCooldownMs` (or add “once per screen” gating) to avoid repeated
  dumps during `perk_selection_screen_update` and `game_over_screen_update`.
- Add a reducer step to diff `auto_dump_player` snapshots per reason (bonus/perk/low health) and emit changed
  offsets to focus MemoryAccessMonitor drills.
- Improve texture name decoding by treating the arg as a struct pointer (probe `*(arg+0x??)` for cstr) or
  hook upstream callsites where the string is still intact. (Now logging both name + path.)
- Extend the reducer to resolve `unmapped_calls.json` entries by module base (grim.dll) so raw addresses
  aren’t lumped together as unknown.
