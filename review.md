Here’s what I see when I line up our current implementation against the authoritative decompiles (mainly `crimsonland.exe_decompiled.c`), and what’s left to do to get HUD rendering to parity.

---

## 1) Survival “debug text” is coming from our draw path, not the original

In **`src/crimson/modes/survival_mode.py`** we unconditionally draw the “Minimal debug text” block whenever the game isn’t over and the perk menu isn’t active:

* `survival: t=... stage=...`
* `xp=... level=... kills=...`
* plus a pause/game over hint

You can see it around **lines ~759–771** in the current file (the exact block starts with `# Minimal debug text.` in your tree).

**Parity expectation:** this is not part of the normal HUD in the decompile HUD path (`hud_update_and_render` → `ui_render_hud`). It should be gated behind `debug_enabled()` (or removed entirely) so it doesn’t show up in normal play.

✅ I’d treat this as a straight “remove / gate behind debug flag” task.

---

## 2) Bonus HUD slots are not matching the decompile (this is the big “bonus timers rendering” gap)

Authoritative behavior lives in:

* **`bonus_hud_slot_update_and_render @ 0041a8b0`** (in `analysis/ghidra/raw/crimsonland.exe_decompiled.c`)
* and slot assignment in **`FUN_0041a810 @ 0041a810`**.

### What the original does (key details)

Per active slot:

1. **Slide animation** (per-frame, in render):

   * If `timer_ptr > 0` (or alt timer > 0): `slide_x += frame_dt * 350`
   * Else: `slide_x -= frame_dt * 320`
   * Clamp to a max of `-2.0`
   * If `slide_x < -184.0`, slot deactivates (with some extra logic to avoid leaving gaps).

2. **Panel placement / size**

   * Normal mode (`cv_uiSmallIndicators == 0`):

     * panel quad at `(slide_x, y - 11)`, size `(182, 53)`, alpha `hud_alpha * 0.7`
   * Small indicators (`cv_uiSmallIndicators != 0`):

     * panel quad at `((slide_x - 100) + 4, y + 5)`, size `(182, 26.5)`, same alpha

3. **Icon**

   * bonus icon at `(slide_x - 1, y)`, size `(32, 32)`, alpha `hud_alpha`

4. **Timer rendering**

   * Always renders progress bars (this is the main missing thing):

     * ratio is `timer_seconds * 0.05` (=> full bar at 20 seconds)
     * width is `100` (normal mode) or `32` (small mode)
   * With no alt timer: one bar
   * With alt timer: **two stacked bars** with different y offsets:

     * small mode: bars at `y + 13` and `y + 19`
     * normal mode: bars at `y + 21` (or adjusted to stack with `-4` offsets)

5. **Label text**

   * Only drawn in **normal mode** (`cv_uiSmallIndicators == 0`)
   * At `(slide_x + 36, y + 6)` (or `y + 2` when alt timer exists)
   * Color is **white** with alpha about `hud_alpha * 0.7`

### What we currently do

In **`src/crimson/ui/hud.py`** (bonus section around **lines ~531+**):

* No slide state at all; we draw at a fixed x (`bonus_x = 4`)
* We reuse the *survival XP panel’s* x offset (`HUD_SURV_PANEL_POS = (-68, 60)`) for bonus panels, which is not what the decompile does (bonus slots live around `slide_x ≈ -2`, not `-68`)
* We **don’t draw progress bars** (timers), we only draw the label text
* We draw the label in `accent_color` (gold-ish), while decompile uses white with lower alpha
* Slot lifetime is controlled in update by `bonus_hud_update()` which deactivates immediately when timers hit zero—this prevents the slide-out animation entirely

### Parity work items for bonus HUD

This is a good “bundle” to tackle together:

* [x] Add per-slot `slide_x` state (init `-184.0` on register, clamp to `-2.0`)
* [x] Stop killing slots immediately on timer expiry; let them slide out until `slide_x < -184`
* [x] Render progress bars:

  * width `100` (normal) / `32` (small)
  * ratio `timer * 0.05`
  * stacked layout when alt timer exists
* [x] Fix panel x/y offsets & sizes to match decompile
* [x] Match text behavior:

  * only in normal indicator mode
  * white color, alpha `hud_alpha * 0.7`
  * y = `+6` (no alt) / `+2` (alt)
* [ ] Implement `cv_uiSmallIndicators` equivalent (likely derived from config; see item 5 below)

---

## 3) Quest HUD is currently the wrong variant (and we’re drawing a custom progress bar in the wrong place)

In the decompile, there are **two different “time HUD” paths**:

* `DAT_004871b3 != 0`: the **quest HUD panels** (two left-side panels, mm:ss timer + “Progress” bar)
* `DAT_004871b4 != 0`: the **“seconds” timer** on the top bar (the one we’re currently using)

The quest panel UI is inside `ui_render_hud @ 0041aed0` under the `DAT_004871b3` branch:

* Draws two `ui_indPanel` quads:

  * top one slides in for the first second (based on `quest_spawn_timeline < 1000`)
  * second is static
* Draws clock table + pointer inside that sliding top panel
* Draws **mm:ss** formatted time, not `"{n} seconds"`
* Draws “Progress” label and a progress bar at fixed positions (no “kills/total” text in that section)

### What we currently do in quest mode

In **`src/crimson/modes/quest_mode.py`**:

* We call `draw_hud_overlay(... show_time=True, show_xp=False)` which gives us the **wrong timer variant** (the top-bar “seconds” clock)
* Then we draw our own kills/total progress bar at `(255, 30)` with custom colors

### Parity work items for quest HUD

* [x] Implement the quest HUD panels (the `DAT_004871b3` branch behavior) instead of the top-bar seconds clock:

  * sliding top panel in first 1000ms
  * mm:ss formatting
  * “Progress” label + bar at decompile positions
* [x] Remove / replace the current ad-hoc kills/total bar (it doesn’t exist in that form in the HUD decompile)
* [x] Reconsider `show_xp=False` in quest mode:

  * since perk progression is enabled in quests (and the game plays the level up SFX), hiding XP/level is likely wrong for parity

---

## 4) Missing: weapon “aux timer” overlay (weapon name panel)

At the end of `ui_render_hud @ 0041aed0`, the original draws a small `indPanel` + weapon icon + **weapon name text** when `player_state.aux_timer > 0`.

We *already* have `PlayerState.aux_timer` and we update it in gameplay (`gameplay.py`), but **`hud.py` never renders it**, so you’ll never see the “weapon name popup”.

Parity item:

* [x] Add the aux-timer panel rendering in `draw_hud_overlay()` (or a helper), matching:

  * panel at approx `x=-12`, y per-player
  * icon at x≈105, and weapon name at x≈8 (see decompile block after bonus slots)

---

## 5) HUD mode flags + “small indicators” config aren’t wired up

In the original:

* `hud_update_and_render @ 0041ca90` derives flags `DAT_004871b0..b4` from `config_blob.reserved0._24_4_`

  * these flags gate which HUD sections render
* `cv_uiSmallIndicators` controls the compact bonus indicator style

In our port:

* We hardcode HUD inclusion per mode (`show_weapon/show_xp/show_time`) and don’t interpret the config field(s) that correspond to these flags
* We have `crimson.cfg` field `hud_indicators` (2 bytes) in `src/grim/config.py`, but it’s unused right now

Parity items:

* [ ] Identify which config bytes map to `reserved0._24_4_` (HUD preset) and to `cv_uiSmallIndicators`
* [ ] Derive the same render flags and pass them into HUD rendering consistently
* [ ] Add a “small indicators” toggle and implement the small-mode branch for bonus slots (it changes both panel geometry and whether text shows)

---

## 6) (Optional but in decompile): boss/target health progress bar

`hud_update_and_render` also draws a floating progress bar above a target creature when `DAT_00487268 != -1`.

If we don’t have that mechanic yet (selection/target tracking), it may be fine to defer, but for full HUD parity it’s a real item:

* [ ] Target creature health bar above world-space creature (camera offset + creature pos)

---

## 7) Quests: “level up” SFX plays, but there’s no way to pick perks (no button/menu)

Your suspicion matches the code path:

* In **quest mode**, we call world update with:

  * `perk_progression_enabled=True`
  * `auto_pick_perks=False`

When `pending_count` increases, **`src/crimson/game_world.py`** plays `sfx_ui_levelup`.
But **`QuestMode` has no perk prompt/menu UI** at all (unlike `SurvivalMode` and `TutorialMode`), so you get the sound and nothing appears.

Parity item(s):

* [ ] Add the perk prompt + perk menu plumbing to **`QuestMode`**

  * reuse the survival/tutorial implementations (or factor into a shared helper)
  * open menu on `keybind_pick_perk` (and/or click), respect `ui_info_texts`
  * pause world update while perk menu is open (as survival does)
* [ ] Once perk UI exists, revisit whether quest HUD should show XP/level panel (very likely yes if perks are active)

---

# Suggested “parity backlog” (prioritized)

### Highest impact (what players notice immediately)

* [ ] **Bonus HUD**: slide + timer bars + correct placement + small indicator mode
* [x] **Quest HUD**: use the quest panel variant (mm:ss + progress panel), remove top-bar seconds timer usage
* [ ] **Quest perk UI**: show level up prompt/menu so the level up sound corresponds to something actionable
* [x] **Remove/gate survival debug overlay** (the “Minimal debug text”)

### Next

* [x] Weapon aux timer overlay (weapon name popup)
* [ ] Wire config-driven HUD presets (`reserved0._24_4_` equivalent) and `uiSmallIndicators`

### Later / conditional

* [ ] Target creature (boss) health bar UI

---

If you want, I can also sketch the exact port of `bonus_hud_slot_update_and_render` into our `hud.py` structure (including the slide-out lifetime behavior), but the key takeaway is: **our current bonus HUD is missing the entire timer/progress-bar path and is anchored at the wrong x, and quest HUD is using the wrong timer variant + missing perk UI.**
