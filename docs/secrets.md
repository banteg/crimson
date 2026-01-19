# Secrets and unlocks (draft)

This page tracks hidden unlock conditions and Easter eggs (Secret Path, secret weapons, etc.) so we can
wire save editing and runtime validation around concrete logic instead of rumor or string hints alone.

## Current status

- We have a cluster of secret-hint strings and a single code path that prints them.
- We have not yet mapped the *actual* unlock logic or any persistent flags.
- No save-file fields are confirmed to drive these secrets.

## Evidence: secret-hint string cluster

Source: `analysis/ghidra/raw/crimsonland.exe_strings.txt` and the startup log path in
`analysis/ghidra/raw/crimsonland.exe_decompiled.c` (inside `crimsonland_main`).

### Strings (static addresses)

- `0x00472e88` — "credits" (menu/label text; not referenced in decompiled code yet).
- `0x00472e90` — "Secret" (menu/label text; not referenced in decompiled code yet).
- `0x00473a8c` — "Brave little haxx0r aren't you?"
- `0x00473b14` — `:D` line about "Wonder what he's up to now..."
- `0x00473b38` — "This is all about fixing city walls with Magic Paint. To stop sinking, you know?"
- `0x00473b8c` — Secret Path hint: click each credits line containing letter `o` to start it.
- `0x00473c3c` — "Inside AlienZooKeeper..." + "CyanYellowRedYellow" + orthogonal projection hint.
- `0x00473ce8` — "Do remember you're probably seeing something that not really meant to see!"
- `0x00473d50` — "I'll tell you a little secret; there are few secret weapons hidden inside the game!"
- `0x00473e34` — `%ReDistrBuildXX%` (build tag string)

### Verified code path (startup console output)

The decompiled `crimsonland_main` (`0x0042c450`) prints the secret-hint cluster via `console_printf`
in a guarded block right after `grim_load_interface()` succeeds and before the usual config load/flow.
The decompiler shows the guard as:

- `if (grim_interface_ptr == grim_interface_ptr + 1) { ... print secret hints ... }`

This condition is nonsensical as written (always false), so treat it as a **decompiler artifact** or
an intentional debug/anti-tamper check that needs disassembly confirmation.

**Implication:** right now, the only *verified* logic around the hints is “print the hint block if the
guard condition passes.” The actual gameplay unlock logic (Secret Path, secret weapons, etc.) is still
unmapped.

## Credits screen code (verified)

The credits screen logic is separate from the startup hint block. We can identify the credits update
loop and its line builder in the `.text` section and verify that it renders the **credits** / **Secret**
labels and consumes the credits line table.

- `credits_screen_update` (`0x0040d800`): update/render loop for the credits screen. It draws the
  `credits` label (`0x00472e88`) and sets the `Secret` label pointer (`0x00472e90`). It calls
  `credits_build_lines` on first entry to populate the table, then loops over visible lines and
  handles clicks (including SFX feedback).
- `credits_build_lines` (`0x0040d090`): populates the credits line table with headings, names, and
  trailing hint lines (including “Click the ones with the round on...”).
- `credits_line_set` (`0x0040d000`): stores a single line + flags in the credits line table.

These functions provide a concrete anchor for the **credits click puzzle** logic, but we still have not
located any code that branches into the **Secret Path** or unlocks secret weapons based on the click
pattern. That logic remains to be found.

## Preconditions and logic (what we do / do not know)

### Secret Path (credits click puzzle)

- **Hinted precondition (string)**: click every credits line containing letter `o` and **avoid clicking**
  other lines; this should start “The Secret Path.”
- **Verified code**: credits UI click handling lives in `credits_screen_update` (`0x0040d800`).
- **Static logic (clicks)**: the click handler checks for lowercase `'o'` (`0x6f`) in the line text. If
  present it sets flag `0x4` (clicked) and plays the bonus sfx; if absent it calls
  `credits_line_clear_flag`, which walks backward to clear the most recently flagged line. This is
  the explicit misclick penalty.
- **Static logic (unlock scan)**: after the per-line loop, `credits_screen_update` scans the entire
  credits line table; if *any* line containing `'o'` is missing flag `0x4`, it bails. If all such
  lines are flagged, it sets `credits_secret_unlock_flag` and injects the secret lines.
- **Runtime capture (2026-01-19)**: when the last required line is flagged, the unlock flag
  `DAT_004811c4` is set and the secret lines are injected into the credits line table at base index
  `DAT_004811bc = 0x54`. The injected lines (all flags `0x4`) are:
  - "Inside Dead Let Mighty Blood"
  - "Do Firepower See Mark Of"
  - "The Sacrifice Old Center"
  - "Yourself Ground First For"
  - "Triangle Cube Last Not Flee"
  - "0001001110000010101110011"
  - "0101001011100010010101100"
  - "011111001000111"
  - "(4 bits for index) <- OOOPS I meant FIVE!"
  - "(4 bits for index)"
  This confirms the secret-line injection is gated by the credits line scan; the **Secret** button
  gating remains unclear, and the actual “Secret Path” transition logic is still unmapped.
- **Secret button transition (static)**: the Secret button press sets `game_state_pending = 0x1a`,
  which maps to `credits_secret_alien_zookeeper_update` (AlienZooKeeper minigame). No other
  “Secret Path” branch is visible in the credits screen decompile.
- **UI gating (static)**: `ui_button_update` for the Secret button runs unconditionally in
  `credits_screen_update`; there is no static gate tied to `credits_secret_unlock_flag`. If the
  button is hidden in practice, that gating likely lives elsewhere (UI data or layout).

#### Secret line decode (5-bit indices)

The hint line **"(4 bits for index) <- OOOPS I meant FIVE!"** indicates the binary strings are
5-bit indices into the ordered word list built from the five quoted lines:

1. Inside
2. Dead
3. Let
4. Mighty
5. Blood
6. Do
7. Firepower
8. See
9. Mark
10. Of
11. The
12. Sacrifice
13. Old
14. Center
15. Yourself
16. Ground
17. First
18. For
19. Triangle
20. Cube
21. Last
22. Not
23. Flee

Decode:

- `0001001110000010101110011` -> `00010 01110 00001 01011 10011`
  -> 2, 14, 1, 11, 19 -> "Dead Center Inside The Triangle"
- `0101001011100010010101100` -> `01010 01011 10001 00101 01100`
  -> 10, 11, 17, 5, 12 -> "Of The First Blood Sacrifice"
- `011111001000111` -> `01111 10010 00111`
  -> 15, 18, 7 -> "Yourself For Firepower"

Final decoded message:

"Dead Center Inside The Triangle Of The First Blood Sacrifice Yourself For Firepower"

### Secret weapons

- **Hinted precondition (string)**: there are “few secret weapons” hidden in the game.
- **Verified code**: the hint string is printed in the startup secret block only. No weapon table flags
  or save fields mapped to secret unlocks yet.

### AlienZooKeeper combination puzzle

- **Hinted precondition (string)**: “Inside AlienZooKeeper” there are combinations; example combo
  “CyanYellowRedYellow” + “orthogonal projection” hint.
- **Verified code (minigame)**: the AlienZooKeeper credits secret is a match-3 board implemented in
  `credits_secret_alien_zookeeper_update` (`0x0040f4f0`). The board is a 6x6 int grid at `0x004819ec`
  (values `0..4`, `-1` empty, `-3` clearing). Swapping tiles calls
  `credits_secret_match3_find` (`0x0040f400`), which returns the first 3-in-a-row match it finds:
  `out_idx` is the **start index** (row-major; leftmost/topmost), and `out_dir` is **orientation**
  (`0 = vertical`, `1 = horizontal`). On a match, the cell is marked `-3`, match masks are written,
  score increments, and the timer adds 2000 ms.
- **Implementation note**: only the **start cell** is marked `-3` on a match, and no clear/fall logic
  is visible in the decompiled update loop (the refill path only checks for `-1`). This supports the
  on-screen text that the puzzle is unfinished, but should be confirmed in runtime.
- **Color mapping (render tint)**: based on the draw path (assuming RGBA), tile values map to:
  `0 = (1.0, 0.5, 0.5)` red/pink, `1 = (0.5, 0.5, 1.0)` blue, `2 = (1.0, 0.5, 1.0)` magenta,
  `3 = (0.5, 1.0, 1.0)` cyan, `4 = (1.0, 1.0, 0.5)` yellow. This likely maps the hint
  **CyanYellowRedYellow** to values `[3,4,0,4]` (inference; needs runtime confirmation).
- **Unlock logic**: the hint string is still only printed in the startup secret block; no map/mission
  unlock branch located yet.

### “Brave little haxx0r” / “not really meant to see”

- **Observed logic**: these lines are printed alongside the hint block under the same guard condition in
  `crimsonland_main`. They likely indicate a debug/redistribution build or an anti-tamper path.
- **Verified code**: only the startup print path; the guard condition needs disassembly confirmation.

## Verified code per hint (current)

All of the hint strings in the cluster are printed from a single guarded block inside `crimsonland_main`
(`0x0042c450`). We have **not** found any other decompiled references yet. Use this list as the definitive
“verified code” map until further xrefs are available:

- `0x00473a8c` — printed in startup secret-hint block.
- `0x00473b14` — printed in startup secret-hint block.
- `0x00473b38` — printed in startup secret-hint block.
- `0x00473b8c` — printed in startup secret-hint block.
- `0x00473c3c` — printed in startup secret-hint block.
- `0x00473ce8` — printed in startup secret-hint block.
- `0x00473d50` — printed in startup secret-hint block.
- `0x00473e34` — printed in startup secret-hint block.
- `0x00472e88` — **no decompiled Xrefs yet** (menu label).
- `0x00472e90` — **no decompiled Xrefs yet** (menu label).

## Open questions

- Which functions gate the Secret Path transition and how are credit clicks tracked?
- Are secret weapon unlocks stored in `game.cfg`, or derived from other state (weapon table flags, globals)?
- Is the startup secret-hint block tied to a “redistribution build” check or another sentinel?
- Are any of these flags version-specific (v1.9.93 vs earlier)?
