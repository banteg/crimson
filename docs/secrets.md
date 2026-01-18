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

- `0x00473a8c` — "Brave little haxx0r aren't you?"
- `0x00473b14` — `:D` line about "Wonder what he's up to now..."
- `0x00473b38` — "This is all about fixing city walls with Magic Paint. To stop sinking, you know?"
- `0x00473b8c` — Secret Path hint: click each credits line containing letter `o` to start it.
- `0x00473c3c` — "Inside AlienZooKeeper..." + "CyanYellowRedYellow" + orthogonal projection hint.
- `0x00473ce8` — "Do remember you're probably seeing something that not really meant to see!"
- `0x00473d50` — "I'll tell you a little secret; there are few secret weapons hidden inside the game!"
- `0x00473e34` — `%ReDistrBuildXX%` (build tag string)
- `0x00472e90` — "Secret" (menu/label text; not referenced in decompiled code yet).
- `0x00472e88` — "credits" (menu/label text; not referenced in decompiled code yet).

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

## Preconditions and logic (what we do / do not know)

### Secret Path (credits click puzzle)

- **Hinted precondition (string)**: click every credits line containing letter `o` and **avoid clicking**
  other lines; this should start “The Secret Path.”
- **Verified code**: none yet. The hint is only confirmed as a string in the startup secret block.

### Secret weapons

- **Hinted precondition (string)**: there are “few secret weapons” hidden in the game.
- **Verified code**: none yet. No weapon table flags or save fields mapped to secret unlocks.

### AlienZooKeeper combination puzzle

- **Hinted precondition (string)**: “Inside AlienZooKeeper” there are combinations; example combo
  “CyanYellowRedYellow” + “orthogonal projection” hint.
- **Verified code**: none yet. No references mapped.

### “Brave little haxx0r” / “not really meant to see”

- **Observed logic**: these lines are printed alongside the hint block under the same guard condition in
  `crimsonland_main`. They likely indicate a debug/redistribution build or an anti-tamper path.
- **Verified code**: only the startup print path; the guard condition needs disassembly confirmation.

## Open questions

- Which functions gate the Secret Path transition and how are credit clicks tracked?
- Are secret weapon unlocks stored in `game.cfg`, or derived from other state (weapon table flags, globals)?
- Is the startup secret-hint block tied to a “redistribution build” check or another sentinel?
- Are any of these flags version-specific (v1.9.93 vs earlier)?
