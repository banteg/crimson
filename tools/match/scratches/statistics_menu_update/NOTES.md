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
empty destructors `statistics_high_scores_button_destroy` through
`statistics_back_button_destroy`.

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

## Total-playtime reuse and allocation bounds

A fresh live disassembly pass separated two playtime regions that the prior
notes treated together. Native session rendering keeps seconds in `ecx`,
occupies `edi`/`ebp` with the renderer and vtable, and spills the long-lived
session-hour value. Native lifetime rendering separately reuses the
total-minutes register in place after deriving total hours.

The recorded two-site `statistics-playtime-allocation-mutations.json` sweep
evaluates all 103/103 singles and pairs across twelve session-lifetime shapes
and seven total-remainder shapes. Its one clean winner replaces the temporary
total-minute-part value with:

```cpp
total_minutes -= total_hours * 60;
```

and passes that reused value to the total-hours draw. This is semantic source
recovery supported directly by native's register dataflow. It gains
`29.8134715025908` weighted bytes without changing the instruction or
reference counts. The scratch moves from
`2555.440414507772/2877` (`88.82309400444115%`) to
`2585.2538860103627/2877` (`89.85936343449297%`), reducing the gap to
`291.74611398963725` bytes while retaining the 280-instruction prefix,
675/676 instructions, and `264/0/5` references. The spec SHA-256 is
`086d6d038f1c5803a348c04af9a040d064be45c372624ec61931d4f56929cbc3`;
the retained source SHA-256 is
`7f5e7366014525a11d2933d6f4a2243314d9b679cb48b660fcc6c923e43bca02`.

Four follow-up sweeps record another 69 fully evaluated variants:

- `session-call-evaluation-mutations.json` tests twelve defined assignment and
  quotient forms intended to evaluate the virtual-call target before the
  remaining arithmetic. One form is byte-neutral; the rest lose at least
  `70.00684459024433` weighted bytes. Its spec SHA-256 is
  `d8aeb7afb01310ef1dccd068b573556d25012eeede05c6ed4b01de0172b5be5d`.
- `button-layout-pointer-mutations.json` tests ten first-member, named-pointer,
  assignment, and independent update-order forms. Pointer and assignment
  aliases are byte-neutral; moving the Back-column X update earlier regresses.
  Its spec SHA-256 is
  `01ca4e40e6f790d831453da60762e2e9f997c95dac5f5f082ffa1275b2c09da3`.
- `music-id-lifetime-mutations.json` tests all 35/35 single and paired local
  lifetime forms for the Typ'o'Shooter and Back music blocks. Every honest
  theme/track local is byte-neutral; reusing the theme local for the final play
  call regresses. Its spec SHA-256 is
  `1287218b3f101e926f7c2f8148bfb6f29c09a1e115d4e658bee5f6008445e6a1`.
- `session-division-lifetime-mutations.json` tests twelve declaration, nested
  scope, compound-division, signed-snapshot, and qualifier forms. Ten compile
  byte-identically and two regress. Its spec SHA-256 is
  `1d8f98377081a13532e59cea36b88a3cd73675864a470433746ec21bb5bf9533`.

The remaining long residual is consequently bounded. Native claims
`edi`/`ebp` for the session renderer/vtable and stores session hours at
`[esp+0x10]`; the candidate retains session hours in `edi` and evaluates the
virtual target later. The rotated registers in the otherwise aligned button
and music blocks inherit from that choice and cannot be changed locally by the
tested semantic spellings. No volatile object, forced spill, register hint,
dead expression, or fake alias is justified.
