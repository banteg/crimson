Here’s what I see from the two zips (`crimson2.zip` + the earlier `crimson.zip` with the Frida artifacts), and what I’d do next if the goal is **“make the decompiles even more readable”** (not necessarily “map every last byte”).

## Where you are now

### 1) Your Ghidra mapping pipeline is already solid

You’ve got the right separation of concerns:

* `analysis/ghidra/maps/name_map.json` = function naming + signatures + comments
* `analysis/ghidra/maps/data_map.json` = globals/data labels + comments (+ some types)
* scripts to apply/export + regenerate headless outputs

That’s the foundation that lets you iterate quickly.

### 2) Function map coverage is good, but there’s still a lot of “noise”

From `crimson2.zip`:

* **name_map.json:** **1,166** entries

  * `crimsonland.exe`: 694
  * `grim.dll`: 472
  * Of those, **~755** are “real renames” (non‑`FUN_…`), and **~411** keep the `FUN_…` name but add a prototype/comment (still valuable).
  * Almost all entries have signatures/comments (great).
* In the *exported decompiled C* you still have:

  * `crimsonland.exe`: **331 / 923** functions still named `FUN_…`
  * `grim.dll`: **619 / 960** functions still named `FUN_…`

A lot of grim.dll “FUNs” are likely third‑party lib internals (png/zlib/etc), so the *readability ROI* there comes more from **quarantining/marking libs**, not lovingly naming each helper.

### 3) Data map is your biggest readability lever right now

* **data_map.json:** **874** entries

  * `crimsonland.exe`: 773
  * `grim.dll`: 101
* Only **~85** entries currently apply a concrete type (the rest are labels/comments).

And most importantly:

* Your current decompiled output still contains about:

  * `crimsonland.exe`: **~2,197** remaining `DAT_########` / `PTR_DAT_########` symbols
  * `grim.dll`: **~395** remaining

That’s why the decompile still “looks busy” even if the *systems* are understood.

### 4) You already have runtime instrumentation that’s paying off

From `crimson.zip`’s Frida outputs:

* `player_unknown_offsets.json` flagged a small set of “unknown but active” offsets.
* You’re already generating evidence summaries, Grim call traces, etc.

That’s exactly the loop you want: **static guess → runtime confirmation → map/types update → regenerate decompile**.

---

## The next steps that will make the decompiles *visibly* cleaner

### 1) Do a “DAT triage pass”: map the *most frequent* unknown globals first

This is the fastest way to improve readability across the entire decompile.

A practical workflow:

1. **Count remaining `DAT_########` tokens** in the decompiled C.
2. Sort by frequency.
3. For the top ~50:

   * extract the enclosing function name + 1–2 context lines
   * add a `data_map.json` entry with a good label + comment (+ type if known)
4. re-export, repeat

I ran that analysis on your current `analysis/ghidra/raw/crimsonland.exe_decompiled.c` and the top “game-relevant” unlabeled globals (not CRT helpers) include things like:

* **`DAT_0047EA54`** (appears a lot)
  Context shows it’s the **console input cursor/length** indexing into the console input buffer.
  → rename suggestion: `console_input_len` (or `console_input_cursor`)
* **`DAT_004DA100`**
  Used as a buffer passed to `GetKeyNameTextA` inside `input_key_name`.
  → rename suggestion: `input_key_name_buf` / `key_name_text_buf`
* **`DAT_00487088`**
  Used in `quest_mode_update` as an **ms timer** controlling SFX/music transitions (thresholds like 0x353, 0x803, etc).
  → rename suggestion: `quest_transition_timer_ms` (or similar)
* **`DAT_0047F4D8`**
  Looks like a string-ish blob used by console init/render.
  → rename suggestion: `s_console_prompt` / `s_console_help_*` (confirm via bytes/strings)

If you only do one “map improvement sprint”, do this one. Every time you replace a hot `DAT_...`, you remove **dozens of ugly tokens** from many functions.

**Small hygiene note:** your `data_map.json` currently has **24 duplicate rows** (same keybind config entries duplicated at the same address). It’s harmless, but cleaning it up keeps tooling output stable and avoids confusion.

---

### 2) Rename a *few* “super-hot” `FUN_…` helpers (the ones that appear everywhere)

This gives outsized readability wins vs. trying to name everything.

The standout in your current export:

* **`FUN_0042FD00`** appears **134 times** in `crimsonland.exe` decompile.

  * The decompiled body clearly:

    * allocates a copy of a string (`operator_new`)
    * walks characters
    * uses `grim_measure_text_width`-style logic
    * replaces spaces with `'\n'` when a running pixel width exceeds a max
  * In other words: **wrap text to width** for perk/bonus/help descriptions.

Rename suggestion:

* `text_wrap_alloc` / `wrap_text_to_width_alloc` / `ui_wrap_text_to_width`

Even if you don’t perfect the signature on day 1, just giving it a real name makes every callsite read like prose.

(Your next “hot FUNs” after that are way less impactful; a couple are tiny pack/compare helpers used as sort keys.)

---

### 3) Invest in **types + parameter names**, not just symbol names

This is the “second order” readability improvement that turns decompiles from *readable* into *pleasant*.

Right now, a lot of signatures still have placeholders (`arg1`, `arg2`, etc.). I counted **hundreds** of map entries with placeholder param names.

Two concrete high-ROI moves:

#### A) Parameter naming on core APIs

Pick the 20–40 functions that sit on hot paths and are read constantly:

* player update/damage
* creature spawn/update
* projectile update/render
* UI element update/render
* quest builder + spawn timeline
* input sampling

Rename parameters to canonical names (`player`, `player_index`, `dt_ms`, `x`, `y`, `count`, `id`, `out`, etc.). That alone makes 3-decompiler diffs dramatically easier.

#### B) “Anchor types” that propagate

You already have a strong `crimsonland_types.h` (33 structs). The trick is: **anchor them at the right globals and function params** so the decompiler *chooses* them everywhere.

Examples of anchors that pay off:

* global pool bases as `creature_t*`, `projectile_t*`, `particle_t*` **plus correct stride usage**
* config blob + save blob + highscore blob as concrete struct types
* menu layout tables / UI widget tables typed as structs (right now they’re still a big source of `DAT_...` + raw pointer math)

One pattern I’d strongly recommend:

* if you can’t express an array type easily via `ApplyDataMap` (it only handles pointer depth),
  create wrapper structs like:

  * `typedef struct { player_state_t players[2]; } player_state_table_t;`
  * `typedef struct { creature_t creatures[0x180]; } creature_pool_t;`

Then you can type the base symbol as `creature_pool_t` and **stop needing** dozens of one-off offset labels.

---

### 4) Fix the “weird casts” by tightening vtable signatures (Grim2D especially)

You already have the Grim2D vtable extraction and a good `docs/grim2d/api.md`.

But some callsites still decompile with bizarre casts (example from `FUN_0042FD00` shows a call that looks like it’s passing a stack address as an `IGrim2D*`).

That’s almost always a sign that:

* the vtable member’s prototype is off (missing/extra parameters, wrong types)
* and/or the calling convention is off

If you make the Grim2D method prototypes accurate, a *lot* of the UI/render code becomes instantly cleaner because Ghidra stops inventing junk casts.

---

## Can you confirm things at runtime? Yes — and you already have the right tools

You already have:

* an “unknown offset tracker”
* Frida probes around perks/bonus/weapon assignment
* evidence summaries

The next step is to turn “unknown offset changes” into “this field is X” with a tight loop:

### A) Watchpoint the *unknown* player offsets and capture the writer

Your Frida results flagged a few offsets near the end of the player struct (`0x34C/0x350/0x354` region) as active.

Two good approaches:

* **Hardware watchpoints** (x64dbg/WinDbg) on `player_base + offset`

  * when it breaks, grab EIP/callstack → that function gets renamed and the field gets named.
* **Frida MemoryAccessMonitor** (if stable for your setup) watching a 16–32 byte region

  * log `Thread.backtrace()` on writes
  * bucket by callsite → most frequent writers are usually the “real semantic owner” of the field

### B) Confirm int vs float storage cheaply

Your player probe notes mention “clip/ammo reads look like float bit patterns”.
That’s exactly where runtime can help:

* read the same field as:

  * `u32`
  * `float`
* log both
* correlate to gameplay actions (reload, bonus apply, weapon switch)

If the value is always an integer but stored as float, you’ll see it snap to exact integer floats. If it’s actually an int, the float interpretation will look chaotic.

### C) Use event-triggered snapshots (you already have this)

Your probe already supports “dump on bonus/perk apply / low health / screen change”.
That’s perfect for:

* “which fields change when perk X triggers?”
* “which fields change when weapon switches?”

Then you can name fields *without* single-stepping.

---

## A concrete “next 10 items” backlog to maximize readability

If I were trying to make the next export feel dramatically cleaner:

1. **Dedup `data_map.json`** (24 duplicate entries; all keybind config labels).
2. Add a script (or quick one-off) to emit **top 50 remaining `DAT_...` by frequency** + enclosing function.
3. Map the top ~20 *game-side* `DAT_...` (console, UI, quest timers, demo timers, menu layout pointers).
4. Rename **`FUN_0042FD00` → `wrap_text_to_width_alloc`** (+ a good comment).
5. Tighten the prototype for the Grim2D text-width function so callsites stop producing nonsense casts.
6. Pick 20 high-traffic functions and replace `arg1/arg2` with real parameter names.
7. Add 2–3 wrapper “array” structs (`*_table_t`) so you can apply clean types at pool bases without relying on pointer math.
8. Run the runtime watchpoint loop on the **player tail offsets** flagged by Frida, name those fields.
9. Identify which grim.dll `FUN_…` clusters are **third-party libs** and mark/namespace them so you stop caring about them.
10. Re-export and re-run your coverage metrics (your `map_progress` approach is good) to ensure the changes actually reduced `DAT_...` / `FUN_...` density.

---

If you want, I can also point to the *single highest ROI* chunk to tackle next (based on your current exports): **menu layout/state**. It’s generating a lot of `DAT_...` pointer math, and once you give those structs real names/types, the menu code becomes *shockingly* readable.
