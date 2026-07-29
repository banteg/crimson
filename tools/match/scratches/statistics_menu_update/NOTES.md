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

A fresh live Binary Ninja pass isolated one UI source-shape question outside
that playtime divergence. After `Sleep(10)` and the default color, native loads
`online_sync_status` once at `0x0043fb3a`, initializes the empty status text at
`0x0043fb40`, and reuses the loaded value for the `1`, `5`, and `6`
comparisons. The bounded `sync-status-snapshot-mutations.json` sweep tested
four explicit local-snapshot declaration/order spellings against that observed
schedule. All four planned singles compiled and were neutral: each remained
at ratio `0.8882309400444115`, fuzzy weighted bytes
`2555.440414507772`, fuzzy gap bytes `321.55958549222805`, 675 candidate
instructions, prefix 280, and references `264/0/5`.

Complete neutral ranking, including generated-source SHA-256:

1. `text-before-snapshot`:
   `c4d243f77ab1e3a1d38e5228310c8914912aa61a633730db89db4a5577674c84`
2. `split-text-after-snapshot`:
   `e076692b4ec53dfc1812dd2a56730491229b0618bfab547c9a356d29b6fd166b`
3. `snapshot-before-text`:
   `5aea060f643cc7ef27d239c6a9320eb1c09e5c81d0f42d6989a98e9c442648d8`
4. `const-snapshot-before-text`:
   `ea8666610f75ad0778fb38202187180c0db36ab829403b01ae89478acfd7d864`

The sweep evaluated 4/4 singles without truncation. No interaction was
eligible because no single improved and the spec has only one mutation site,
so `scratch.cpp` remains unchanged at SHA-256
`6f5647fe2b409cce6cb02a27ec508052d95b837b6bffc499e295f25ae35e752c`.
The spec SHA-256 is
`f8c254410d319948906f150a0ee4224f1375bcd1f794f9228553d87a2edce28c`;
the recorded `experiments.jsonl` SHA-256 is
`e077cd9cba0928383cb93400c050f6bd81de76111fd7bbc32117ee1ce4ab23d6`.
This sweep deliberately did not repeat the already-rejected playtime
quotient/remainder forms.

No volatile state, dummy use, forced address, fake alias, inline assembly, or
dead arithmetic is used. The callback remains WIP only for compiler scheduling,
not for missing recovered behavior. It is therefore `semantic-complete` with
only a `compiler` residual. The five audit mismatches pair the three adjacent
music IDs and their already-present mute/play calls after the playtime
scheduling divergence; they remain visible and unaliased rather than being
treated as independent reference debt.

## Session-playtime lifetime and call-shape bounds (2026-07-29)

Live native `0x0043fa8b` confirms the recovered seconds, minutes, and hours
arithmetic, including the magic divides, interleaved renderer/vtable loads,
the spilled hour value, and the third unused formatting argument. Two
recorded sweeps test thirteen natural spellings around that sequence without
changing the retained source.

`session-playtime-lifetime-mutations.json` evaluates seven declaration and
renderer-snapshot placements. Naming seconds is byte-neutral. The five early
renderer forms trade one mismatched reference for one resolved reference but
lose 55.36787564766837 weighted bytes; moving the renderer after all
arithmetic loses 178.8808290155439 weighted bytes and eleven aligned
references. Its spec SHA-256 is
`c7e02701c102d1f1d90eb9212a249ef798629e7b91d67476d0acd9310f64ad47`.

`session-playtime-call-mutations.json` evaluates six call-expression forms.
The two modulo spellings recover the native 676-instruction count and improve
the reference audit to `265/0/4`, but lose 57.21704172670661 weighted bytes.
The four fully inlined arithmetic forms emit 678 instructions and lose
175.6472091901942 weighted bytes plus eleven aligned references. Its spec
SHA-256 is
`cb691dfef8cf77d81e4ef3eb00da8bda448ff22d43839b8fc1adb990542c5349`.
Because both apparent instruction/reference wins worsen the overall native
alignment, neither tradeoff is retained.
