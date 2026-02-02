Below is what I’m seeing when I diff **our current ui_menuPanel rendering** against the **runtime capture** (marked frames). I’m focusing strictly on the **panel texture (`ui\ui_menuPanel`, tex id 63)**: geometry, UVs, shadow pass, and slide timing/width.

---

## Runtime panel “truth” extracted from the capture

There are **two distinct render variants** for `ui_menuPanel` in the capture:

### Variant A — `quad_mode = 4` (single quad, “trimmed”)

* **Local geometry (screen-space relative to element offset):**
  `x: 21 → 531` (**510 px**)
  `y: -81 → 173` (**254 px**)
* **UV trim (inset):** `u: 1/512 → 511/512`, `v: 1/256 → 255.5/256`
  (so we *don’t* sample the outermost border pixels)
* **Draw calls:** 1 shadow + 1 main
* Used in: **state 2**, plus the “side panels” in **states 3, 14–16**

### Variant B — `quad_mode = 8` (3-slice vertical panel)

* **Local geometry (base):**

  * `x: -63 → 447` (**510 px**)
  * `y0=-81, y1=57, y2=81, y3=197`
    Heights: **top 138**, **mid 24**, **bottom 116** → total **278**
* **Local geometry (tall):**

  * same x/y0/y1, but `y2=181, y3=297`
    Heights: **top 138**, **mid 124**, **bottom 116** → total **378**
* **UVs per slice:**

  * u always `1/512 → 511/512`
  * v:

    * top: `1/256 → 130/256`
    * mid: `130/256 → 150/256`
    * bottom: `150/256 → 255.5/256`
* **Draw calls:** 3 shadow (top/mid/bot) + 3 main (top/mid/bot)
  and importantly: **all shadow slices first, then all main slices**
* Used in: **state 1, 4, 6, 8, 11, 14–17**, and as the “main” panel in some dual-panel screens.

### Shadow pass (both variants)

* Shadow is **offset by (+7, +7)** in screen pixels.
* Shadow tint is **0x44444444** (as seen in capture).
* Shadow blend is the special “darken” setup (we already have that in `crimson/ui/shadow.py`).

---

## Global fixes (affect every state that draws `ui_menuPanel`)

* [x] Introduce a single source of truth for `ui_menuPanel` geometry + UV trims:

  * [x] Variant A (`quad_mode=4`): local bbox `(21,-81)-(531,173)` and src rect `(x=1,y=1,w=510,h=254.5)`
  * [x] Variant B (`quad_mode=8`): local x `(-63..447)`, y slices `(-81..57..81/181..197/297)` and src slice rects:

    * top: `(1,1,510,129)`
    * mid: `(1,130,510,20)`
    * bottom: `(1,150,510,105.5)`
* [x] Refactor `draw_menu_panel()` so it **does not derive slice heights from texture scaling**; it should use the **captured geometry heights** (138/24/116) and only expand the mid slice by `delta_h`.
* [x] Fix `draw_menu_panel()` draw ordering to match capture: **all 3 shadow slices first, then all 3 main slices** (right now we interleave shadow/main per slice).
* [x] Stop using `MENU_PANEL_WIDTH=512` and `MENU_PANEL_HEIGHT=256` as *drawn* dimensions for the panel; those are texture dimensions, but runtime draws **510-wide** panels and either **254 / 278 / 378** tall depending on variant.
* [x] Update slide width for panels to **510** everywhere (capture slide is ±510, not ±512).
* [x] Extend `_ui_element_anim()` (or wrapper) to support **direction_flag** so right-sliding panels can use **+510 → 0** (needed in states 3, 14–16).

---

## State 0 — Main menu

(Doesn’t draw `ui_menuPanel` in the marked frames.)

* [x] No panel-specific action.

---

## State 1 — Play Game menu

**Runtime capture**

* Variant: **`quad_mode=8` sliced**, **base 278** tall
* pos: `(-45, 300)` (already includes widescreen shift in capture)
* open bbox (main): `(-108,219) → (402,497)`
* shadow bbox is +7/+7
* slide timeline: **start=300ms end=0ms**, width=510, direction_flag=0

**Our current**

* We draw a **single 512×256 quad** (no slicing)
* Panel bbox open is effectively `(-141,218) → (371,474)` (wrong size/offset)
* Panel shadow is currently drawn **without the +7/+7 offset** in `PanelMenuView._draw_panel`

Fix plan:

* [x] Update `PanelMenuView._draw_panel` (`src/crimson/frontend/panels/base.py`) to use **Variant B (sliced)** for this state.
* [x] Use **base height 278** (not 256) for the Play Game panel.
* [x] Apply **UV trimming** (x=1..511, y starts at 1, bottom ends at 255.5).
* [x] Fix panel shadow offset: add `UI_SHADOW_OFFSET` to panel shadow draws (or have the panel renderer do it).
* [x] Update slide width passed into `_ui_element_anim()` for the panel from **512 → 510**.
* [x] Recompute any content anchoring in `play_game.py` that depends on the old `MENU_PANEL_OFFSET_X/-Y` assumptions (panel_left/panel_top will change when we switch to the real geom x0/y0).

---

## State 2 — Options menu

**Runtime capture**

* Variant: **`quad_mode=4` single quad**
* open bbox: `(-24,219) → (486,473)` (510×254)
* slide: start=300/end=0, width=510, direction_flag=0

**Our current**

* Uses the same `PanelMenuView` panel as Play Game (512×256, wrong origin)
* Shadow offset bug applies here too

Fix plan:

* [x] Make Options use **Variant A (quad_mode=4)**, not the sliced panel.
* [x] Render with trimmed src rect `(1,1,510,254.5)` into dst size **510×254** using local geom `(21,-81)`.
* [x] Fix shadow offset (+7/+7) on the panel.
* [x] Change panel slide width in this state to **510**.
* [x] Adjust Options content layout offsets after panel bbox changes (it will move significantly: runtime panel is much farther right than our current).

---

## State 3 — Controls configuration

**Runtime capture**
Two panels:

1. **Left panel:** Variant A `quad_mode=4`, pos `(-165,290)`, open bbox `(-144,209)→(366,463)`, direction_flag=0, start=300/end=0
2. **Right panel:** Variant B `quad_mode=8` **tall 378**, pos `(674,200)`, open bbox `(611,119)→(1121,497)`, direction_flag=1, start=300/end=0 (slides from right)

**Our current**

* `frontend/panels/controls.py` is a placeholder and uses the standard single-panel base behavior (wrong count, wrong positions, wrong variants).

Fix plan:

* [x] Implement the **dual-panel layout** for state 3:

  * [x] Left: Variant A quad panel at the captured position.
  * [x] Right: Variant B sliced tall panel at the captured position.
* [x] Add direction-aware slide (+510 → 0) for the right panel (direction_flag=1).
* [x] Ensure both panels use correct UV trims and shadow offsets.
* [x] Verify the right panel being partially off-screen (x2=1121) is intended and match it exactly.

---

## State 4 — Statistics menu

**Runtime capture**

* Variant: **`quad_mode=8` sliced**, **tall 378**
* pos `(-5,275)`; open bbox `(-68,194) → (442,572)`
* start=300/end=0, direction_flag=0

**Our current**

* `frontend/panels/stats.py` uses `PanelMenuView` defaults (pos -45/210, height 256, single-quad)
* So: wrong variant, wrong size, wrong pos, shadow offset bug

Fix plan:

* [x] Switch Statistics panel to **Variant B tall (378)** and **pos (-5,185)** (then widescreen shift).
* [x] Fix shadow offset and UV trims.
* [x] Update slide width 512→510.
* [x] Re-anchor the contents once the panel geometry is correct (our current stats content is not the classic menu anyway, but at minimum the panel itself should match).

---

## State 6 — Perk selection (in-game)

**Runtime capture**

* Variant: **`quad_mode=8` sliced**, **tall 378**
* pos `(-45,200)` (base y=110 + widescreen shift)
* timeline start=400/end=100 (100ms delay, 300ms slide), direction_flag=0
* slide range **-510 → 0**
* open bbox `(-108,119) → (402,497)`

**Our current**

* Uses `perk_menu.draw_menu_panel()` which:

  * derives slice heights from texture scale (top 130 / mid huge / bottom 106) → wrong proportions
  * uses full texture UVs (no 1px trim / no 255.5 bottom) → sampling mismatch
  * uses **512** widths and slide widths
  * panel placement in `PerkMenuLayout` is based on `pos+offset(20,-82)` → wrong for quad_mode=8 (should use local x0=-63)
  * draw order interleaves shadow/main per slice → not matching capture

Fix plan:

* [x] Rewrite `draw_menu_panel()` (`src/crimson/ui/perk_menu.py`) to render **Variant B** using the captured geometry and UV trims.
* [x] Update in-game perk panel width to **510** and height to **378** (not 512×379).
* [x] Change layout anchor: compute panel left/top from **pos + slide + (geom_x0/geom_y0)**, not from `offset (20,-82)`.
* [x] Match slide timing: add the 100ms “hold hidden” (end_ms=100) before sliding, and use width 510.
* [x] Fix draw ordering to “all shadows first, then mains”.

---

## State 8 — Quest results screen

**Runtime capture**

* Variant: **`quad_mode=8` sliced**, **tall 378**
* pos `(-45,200)` (base y=110 + widescreen shift)
* timeline start=400/end=100, direction_flag=0
* open bbox `(-108,119) → (402,497)`

**Our current (`src/crimson/ui/quest_results.py`)**

* Uses `QUEST_RESULTS_PANEL_BASE_X = 180` (panel is shifted right vs runtime)
* Uses width=512 and height=379
* Uses slide duration 250ms, not the captured 100ms delay + 300ms slide
* Uses current `draw_menu_panel()` (wrong slice proportions + no UV trim)

Fix plan:

* [x] Remove/verify the extra `QUEST_RESULTS_PANEL_BASE_X` offset (runtime panel is anchored directly off `pos_x + slide_x`).
* [x] Switch quest-results panel to **Variant B tall** with width **510** and height **378**.
* [x] Match timing: timeline start=400/end=100, linear slide, width 510.
* [x] Use the corrected `draw_menu_panel()` (geometry-based slices, UV trims, correct shadow ordering).
* [x] Re-anchor quest-results text once panel position is corrected (it will move ~180px left).

---

## State 11 — Quest select menu

**Runtime capture**

* Variant: **`quad_mode=8` sliced**, **tall 378**
* pos `(-5,275)` (base y=185 + widescreen shift)
* timeline start=300/end=0, direction_flag=0
* open bbox `(-68,194) → (442,572)`

**Our current (`src/crimson/game.py` QuestsMenuView)**

* Draws panel at `QUEST_MENU_BASE_X + MENU_PANEL_OFFSET_X` → uses -96 instead of -63, so panel is ~33px too far left.
* Uses width=512 and height=379.
* Uses current `draw_menu_panel()` scaling logic (wrong slice proportions + no UV trim).
* Slide width uses 512.

Fix plan:

* [x] Use **pos_x=-5,pos_y=185** as the element anchor, then apply local geom x0=-63/y0=-81.
* [x] Switch panel width to **510**, height to **378**.
* [x] Update `_ui_element_anim(width=...)` calls to use **510**.
* [x] Use corrected `draw_menu_panel()` (Variant B tall, correct UV trims, correct draw ordering).

---

## State 14 — High scores

**Runtime capture**
Two panels:

* Main: Variant B tall, pos `(-35,275)`, dir=0
* Side: Variant A quad, pos `(609,290)`, dir=1 (slides from right)
* Both timeline start=300/end=0

Fix plan:

* [x] When we implement state 14, render both panels using the shared renderer:

  * [x] Main panel = Variant B tall at (-35,185)+shift.
  * [x] Side panel = Variant A quad at (609,200)+shift with direction_flag=1.
* [x] Ensure right-side panel slide uses **+510 → 0**.

---

## State 15 — Weapons database

(Panel usage matches state 14: one tall sliced + one quad side panel.)

* [x] Render both panels using the shared renderer (layout matches state 14).
* [x] Ensure right-side panel slide uses **+510 → 0**.

---

## State 16 — Perks database

(Panel usage matches state 14: one tall sliced + one quad side panel.)

* [x] Render both panels using the shared renderer (layout matches state 14).
* [x] Ensure right-side panel slide uses **+510 → 0**.

---

## State 17 — Credits

**Runtime capture**

* One panel: Variant B tall, pos `(-5,275)`, start=300/end=0, dir=0

Fix plan:

* [x] Render credits panel with Variant B tall at pos (-5,185)+shift using width 510, height 378.
* [x] Use corrected `draw_menu_panel()` and slide width 510.

---

If you want, I can also turn this into a **single “panel spec” markdown file** under `docs/` (with the exact local coords + UVs + variants) so we stop re-deriving these numbers in multiple screens.
