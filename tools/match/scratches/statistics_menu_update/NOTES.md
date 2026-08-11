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

Verified WIP: 93.26%, with 675 candidate instructions against 676 native and
audited references `276/0/0`. The remaining substantive region is integer
register allocation for the two playtime calculations. Native loads the
renderer between the minute and hour quotients, spills the session-hour value,
and reuses quotient products for both remainders; the natural VC6 candidate
keeps the session hour in a register and emits one `idiv` in the lifetime
block. Literal `% 60`, direct minute-count, and equivalent quotient/remainder
source forms were tested and reduce the match. With the downstream
total-renderer ownership fixed, a session renderer capture at the native
seconds/minutes boundary now improves the match; the total-hours branch-local
capture preserves the native widget ownership and resolves all references
without aliasing distinct operands.

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
only a `compiler` residual. All references now audit cleanly; the three music
IDs remain distinct and unaliased.

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

## Total-renderer ownership and widget publication (2026-08-09)

Focused native inspection separated the five-call button-coordinate run at
`0x0043fdf9..0x0043fe8b` from the earlier session-hours arithmetic. After the
F1 key gate, native reloads `grim_interface_ptr` into `eax` at `0x0043fdc8`
for the total-hours draw. The following widget addresses then cycle through
`edx`, `eax`, `ecx`, `edx`, and `eax`. The prior direct-global draw left its
renderer pointer in `edx`, rotating every otherwise-identical widget address
register and the later reference schedule by one.

Capturing `total_renderer` inside the taken branch, after the key test and
immediately before the draw, recovers that natural ownership boundary. It also
preserves the fact that the key call precedes the renderer reload. The complete
five-widget publication run becomes exact without changing its arithmetic,
calls, or coordinate storage. The retained result improves from
`2585.2538860103627/2877` (**89.859363%**) to
`2610.8082901554403/2877` (**90.747594%**), a gain of **25.554404 weighted
bytes**. It keeps the 280-instruction prefix and 675/676 instruction count,
while references improve from `264/0/5` to fully clean **`276/0/0`**. Current
source SHA-256 is
`85f19ac8e976657c26a299cf0e99f2410b0b13d35caaaf766da00545a7bd5d45`.

## Session renderer and quotient ownership (2026-08-09)

The total-renderer boundary above changes the tradeoff for the older session
playtime ownership hypothesis. Native finishes the seconds quotient at
`0x0043fa95`, loads `grim_interface_ptr` at `0x0043fa97`, starts the minute
quotient at `0x0043fa9d`, and loads the renderer vtable at `0x0043faa3` before
that quotient finishes. Naming `session_seconds` and capturing
`session_renderer` immediately after it is the natural source boundary that
matches the first of those two native ownership events.

On the branch-local total-renderer baseline, this source shape improves from
`2610.8082901554403/2877` (**90.747594%**) to
`2683.2124352331607/2877` (**93.264249%**), a gain of
**72.404145 weighted bytes**. It keeps the 280-instruction prefix, 675/676
instruction count, and fully clean `276/0/0` references. Declaring the
session-hour local before that capture is byte-neutral. Rechecking the one
previous call-lifetime form that recovered the 676th instruction reaches only
**92.751479%**, so its quotient/modulo tradeoff remains inferior and is not
retained.

The remaining session residual is narrower: the candidate retains the
renderer in `ebp` and the session hour in `edi`, while native retains the
renderer in `edi`, its vtable in `ebp`, and spills the hour at
`[esp+0x10]`. No artificial dependency or forced spill is justified. Current
source SHA-256 is
`1f05054f3a40357f922e1127348bc36f0cba975e8130101ddbc2ddd272dfe591`.

## Current session scheduling replay (2026-08-12)

The older experiment records predate the retained renderer boundaries, so the
remaining session region was replayed from the current **93.264249%** source
rather than treated as settled by those notes. Live native comparison confirms
that the first mismatch still starts at the same ownership split: native loads
the renderer into `edi` and its vtable into `ebp` before completing the
minute/hour arithmetic, then spills the hour at `[esp+0x10]`. The candidate
keeps the renderer in `ebp`, delays the vtable load until the call, and retains
the hour in `edi`.

Three complete current-baseline sweeps bound the ordinary source shapes:

- `current-session-call-evaluation-mutations.json` (SHA-256
  `e98bb595ba7ccc9a2799cb936f339175d596fcb65ba4d805ab8a966f6b59fb3e`)
  evaluates all eight defined call-argument forms. One assigned-hour spelling
  is byte-neutral. Modulo forms lose **63.886010 weighted bytes**, direct
  division by 3600 loses **84.768976**, and the independent-expression forms
  lose **120.685109**.
- `current-session-renderer-ownership-mutations.json` (SHA-256
  `b7d33d8ad83b6904bdc1d2a2a2f34493236392e6673fb72b3ded99ec6af09ad5`)
  evaluates all seven pointer/reference, qualifier, declaration, and assignment
  placements. Six are byte-neutral; moving the renderer capture after the hour
  quotient loses **106.476684 weighted bytes**.
- `current-session-quotient-lifetime-mutations.json` (SHA-256
  `3ddb8166bdeb2cdf2a9208076dc9204e0a662c0ad168656a6d7e2dc97c597992`)
  evaluates all nine defined assignment, compound-division, named-result, and
  remainder-reuse forms. Seven are byte-neutral. Modulo loses **63.886010
  weighted bytes**, while reusing `session_minutes` for the remainder loses
  **106.476684**.

No current variant improves the canonical source, so none is retained. The
remaining allocation would require an artificial vtable dependency, forced
spill, or register coercion; those are not honest decompilation evidence. The
canonical result remains `2683.2124352331607/2877` (**93.264249%**), with a
280-instruction exact prefix, 675/676 instructions, and clean `276/0/0`
references.
