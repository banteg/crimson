# `statistics_menu_update`

Native target: `crimsonland.exe` at `0x0043f550` (2877 bytes, 676
normalized instructions).

Live Binary Ninja disassembly/HLIL, with independent IDA and Ghidra
decompilation, recovers the complete Statistics menu callback:

- eight function-local static buttons and their shared byte-sized constructor
  guard;
- the statistics panel anchor, title quad, session playtime, lifetime
  playtime-on-F1, online synchronization state, and update-check notice;
- High Scores, Weapons, Perks, Credits, update-check, Back, and Escape routing;
- high-score quest-stage clamping and table reload;
- Typ'o'Shooter setup, music transitions, fade state, and the final update
  notice reset.

The static objects are mapped as `statistics_high_scores_button`,
`statistics_weapons_button`, `statistics_perks_button`,
`statistics_credits_button`, `statistics_typo_button`,
`statistics_mods_button`, `statistics_update_button`, and
`statistics_back_button`. Their eight native atexit thunks are the empty
destructors `nullsub_52` through `nullsub_45`.

Several native asymmetries are intentional and retained:

- online synchronization disables Back, Update, Mods, Credits, Weapons, and
  High Scores, but not Perks or Typ'o'Shooter;
- Mods is initialized and toggled but never updated or activated here;
- Typ'o'Shooter and Update are activation-tested without a local
  `ui_button_update` call;
- the session format has two conversion fields although native passes three
  integer arguments;
- Typ'o'Shooter mutes three tracks without starting another, while both Back
  paths mute the same three and restart the Crimson theme.

The reconstructed panel expression gives the exact native `0x18`-byte stack
frame and a 280-instruction exact prefix. Native x87 order around the Back
button supports two explicit y advances before the x-column shift; spelling
those independent layout operations in that observed order improves alignment
without changing or padding behavior.

Verified WIP: 88.82%, with 675 candidate instructions against 676 native and
audited references `264/0/5`. The remaining substantive region is integer
register allocation for the two playtime calculations. Native loads the
renderer between the minute and hour quotients, spills the session-hour value,
and reuses quotient products for both remainders; the natural VC6 candidate
keeps the session hour in a register and emits one `idiv` in the lifetime
block. Literal `% 60`, direct minute-count, explicit renderer-cache, and
equivalent quotient/remainder source forms were tested and all reduced the
match. The five reported reference mismatches occur after that scheduling
divergence; their distinct real operands were deliberately not aliased.

No volatile state, dummy use, forced address, fake alias, inline assembly, or
dead arithmetic is used. The callback remains WIP only for compiler scheduling,
not for missing recovered behavior.
