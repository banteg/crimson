# `ui_render_hud`

Native target: `crimsonland.exe` at `0x0041aed0` (7,081 bytes).

Live Binary Ninja evidence recovers the complete gameplay-facing HUD callback:
top frame, pulsing player hearts, weapon icons, health and ammo bars, Quest
clock/progress and stage banners, Rush/Typ-o-Shooter timer, smoothed Survival
XP, bonus slots, and per-player weapon-change popups.

This reconstruction intentionally preserves two native multiplayer details:
the second heart inherits player one's low-health pulse speed as its baseline,
and weapon-change popup rows advance only when a player's popup is active.
Bonus/pop-up layout starts at Y=78 and advances by 43 only when the XP panel is
present.

The dword at `0x004902fc` has exactly one native xref: an unconditional zero
store immediately before the quest spawn-count accumulation. It is retained as
`quest_progress_reserved_zero`; no stronger semantics are claimed.

The default VC6.5 `/O2 /GB /W3 /GR-` build scores **85.64%** with the exact
native `0x34`-byte stack frame and exact 1,824/1,824 instruction count. The
reference audit is 385 resolved, 0 unresolved, and 0 mismatched. Writing the
quest-clock leading-zero case as the fallthrough branch matches the native
basic-block order and resolves both clock-format references. Keeping the
player-zero weapon-id expression inside both icon-layout branches lets VC6
hoist the common load in the native order, removing the final audit mismatch
and 73.76 fuzzy-gap bytes. No reference is hidden or force-accepted.

Remaining differences are ordinary old-MSVC register allocation, stack-slot
coloring, and a few equivalent control-flow layouts. In particular, the
reconstruction deliberately keeps the native ammo-class, XP smoothing, quest
fade, and popup timer branches in their evidenced source shape rather than
adding inert match-only scaffolding.

The HUD ammo-class lookup now names the canonical
`weapon_storage_entry_t::ammo_class` field instead of multiplying the weapon
id by a raw 31-dword row stride. The source-only type correction is
byte-neutral. With the branch-order recoveries above, final validation remains
1,824/1,824 instructions at 85.6360% with `385/0/0` references.

A systematic codegen audit requested 59 profiles. The 45-profile compiler
matrix covered every installed backend (`msvc6.0`, `msvc6.5`, `msvc6.5pp`,
`msvc6.6`, and `msvc7.0`) across optimization level, `/GB`/`/G5`/`/G6`,
inlining, frame-pointer, and exception variants. Fourteen additional VC6.5
checks covered `/Op`, `/Oi-`, `/Ob0`, `/Os`, `/Ot`, `/Og-`, `/Gf`, `/Gy`,
debug-info, packing, and unsigned-char toggles. VC6.0, VC6.5, and VC6.6 emit
the same best result. Patched VC6.5 falls to `73.30%`; `/G6`, `/Oy-`, and
`/GX` fall to `76.12%`, `76.93%`, and `81.14%`; VC7.0 rejects this source.
No `scratch.conf` override is justified.

Entry-region probes tested the first native `[esp+0x1c]` versus candidate
`[esp+0x18]` slot difference without introducing dead state. Moving `hud_y`
or the complete tail-layout local set to function scope is byte-neutral,
showing that declaration order alone does not explain VC6's stack coloring.
Initializing `hud_y` at entry extends a lifetime absent from the native code
and regresses to `79.16%`, 1,827/1,824 instructions, a zero-instruction prefix,
and `378/0/0` references, so it is rejected. The source and canonical profile
remain unchanged.

The bounded `panel-alpha-declaration-lifetime` mutation sweep isolates the
first mismatch without changing the native expression schedule. Live Binary
Ninja target `3023:2:9499448411019345244` shows the native `0x34`-byte frame
calling `grim_set_rotation`, `grim_set_config_var`, and `grim_set_uv`, then
loading `transition_alpha` at `0x0041af4d`, multiplying by `0.7f`, and storing
the long-lived panel alpha at `[esp+0x1c]`; the baseline follows that same
order but colors the value at `[esp+0x18]`. The schema-1 sweep therefore moved
only the declaration point while keeping the assignment after `grim_set_uv`.

The persisted spec SHA-256 is
`78341a8c7ee6a7a17e12749a64758ab26369c83284aa855a81e1827e2660b998`;
the unchanged baseline `scratch.cpp` SHA-256 is
`69a68d8ed7fe1bd1dde1e2a1fe9222da0d0cb7f7f2ec0bab30fe0cfa8789ba74`.
All five planned single-site variants were evaluated and recorded. Their
complete harness ranking is:

| Rank | Declaration placement | Source SHA-256 |
| ---: | --- | --- |
| 1 | post-transparency | `7eee407814f26c3d3324fad2e5eda758a34550b59d7e58b30cca4654cdea4688` |
| 2 | post-rotation | `0a386f8f1a7dfb5df84fcdbc2af769ce2bbd912a6147558bfe7c74514ca9dbab` |
| 3 | post-config | `2183c4e82ec65a4a1e87472350bb58d05bcbc1de33dba189a7200e747f14751e` |
| 4 | function entry | `f12d4854bdfc77205a7a999b7a65b12fea8c49c21d2df15f630b61d9482d9b1e` |
| 5 | adjacent split | `34e49511b4151d4fda3751237bcdca474c862a25d1eac7eb9eabbea9c5dc7bd8` |

Every variant is byte-neutral against the baseline: `85.6359649122807%`,
6,063.882675 fuzzy-weighted bytes, 1,824/1,824 instructions, prefix 42,
`385/0/0` references, and first target/candidate mismatch offsets `143/143`.
The record has `best_improves=false` and no winner. Because no single-site
mutation improved, no interaction sweep was justified; the semantic source
remains unchanged.

## Popup panel-Y materialization sweep

A second bounded pass selected the coherent weapon-popup tail at
`0x0041c87b..0x0041ca49`. Live Binary Ninja disassembly shows native
recomputing `icon_y - 12` with `lea eax, [esi-0xc]` at `0x0041c8ea`, then
advancing only the text and icon Y values by 32 at `0x0041ca2d..0x0041ca49`.
The candidate preserves the same panel coordinate and loop behavior, but VC6
strength-reduces the panel Y expression into a third induction value.

The schema-1 `popup-panel-y-materialization` sweep tested four natural named,
split, direct-initialized, and const spellings. Its persisted spec SHA-256 is
`6bafaccaf35407cd46d0311480edd37d014e10756581be74d9a027a65a9424dc`;
the unchanged source SHA-256 is
`69a68d8ed7fe1bd1dde1e2a1fe9222da0d0cb7f7f2ec0bab30fe0cfa8789ba74`.
All 4/4 planned singles are byte-identical to the baseline:
`6063.882675438596/7081` weighted bytes (`85.6359649122807%`), gap
`1017.1173245614036`, 1,824/1,824 instructions, prefix 42, and `385/0/0`
references. The recorded sweep has `best_improves=false`; no source change or
interaction sweep is justified.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live Binary Ninja decompilation confirms the heart, weapon/ammo, Quest,
timer, Survival XP, bonus-slot, and weapon-popup paths through the native
`0x0041aed0..0x0041ca79` extent. IDA and Ghidra independently retain the same
signature and six named helper calls. The first localized mismatch is only the
native `[esp+0x1c]` versus candidate `[esp+0x18]` temporary slot; the next
regions likewise preserve the same operations and audited references in
different legal stack slots.

## Survival XP progress-local materialization sweep

The highest fuzzy-weighted region outside the completed popup-panel sweep is
the Survival XP threshold/progress-bar sequence at
`0x0041c6d6..0x0041c75b`: 93.1 weighted bytes, a 0.7 regional ratio, and
7/0/0 regional references. Live Binary Ninja target
`crimsonland.exe.bndb` shows the native code preserving the recovered source
order: calculate the previous level threshold, override it with zero at level
one, construct the RGBA progress color, convert `hud_y + 13` for the progress
position, calculate the next threshold, divide the XP delta by the threshold
delta, and call `ui_draw_progress_bar`.

The candidate performs the same operations in the same order. The region's
nine changed instructions are stack coloring only: native reads the long-lived
panel alpha from `[esp+0x1c]` where the candidate uses `[esp+0x18]`, and VC6
chooses different temporary slots for the integer-to-float conversion,
progress-position fields, and retained `pow` result. All seven masked operands
remain aligned, so native evidence does not justify changing the recovered XP
semantics.

The bounded schema-1 `xp-progress-local-materialization` sweep tested all 6/6
planned single-site variants. Its persisted spec SHA-256 is
`ca3ca914b2242059078cb5affed90b30b91b692613068624bd6d58109e8089fa`;
the canonical source remains
`69a68d8ed7fe1bd1dde1e2a1fe9222da0d0cb7f7f2ec0bab30fe0cfa8789ba74`.
Named and split integer-Y forms and a named float-Y form are byte-neutral:
6,063.882675/7,081 weighted bytes (`85.6359649122807%`), gap
1,017.117325, 1,824/1,824 instructions, prefix 42, and `385/0/0` references.
An explicit recorded probe of the top natural `split-int-y` spelling confirms
an exact zero delta and source SHA-256
`86b2e7957db56b0b58a7ff31098fdfb86db6cdc4a94a97469aed0bd6d1745585`.

The two named-alpha variants regress by 11.646382 weighted bytes to
6,052.236294 (`85.47149122807017%`), gap 1,028.763706, and 384/0/0 aligned
references while leaving instruction count and prefix unchanged. VC6.5 rejects
the copy-initialized position spelling at compile time. The sweep has
`best_improves=false` and no winner, so no interaction batch or source change
is justified.

## Native-guided ammo, quest-banner, and popup wave

Fresh live Binary Ninja evidence was taken from target
`3023:2:9499448411019345244`, native `ui_render_hud` at
`0x0041aed0` (7,081 bytes, 1,824 instructions). This wave began at
6,063.882675438596/7,081 weighted bytes (`85.6359649122807%`), gap
1,017.1173245614036, 1,824/1,824 instructions, prefix 42, and `385/0/0`
references. Five bounded, recorded changes recovered native source structure:

- The ammo-bar alpha now duplicates the `grim_set_color` call across the
  filled/unfilled branch. Native `0x0041b7a9..0x0041b7d9` loads the interface
  and virtual call target before branching on the bar index, then merges the
  two call paths. The named ternary hid that source shape. The
  `ammo-alpha-callsite/duplicated-call` winner gained 32.72823764064651
  weighted bytes and one aligned reference while removing one candidate
  instruction.
- The weapon-popup row now advances `icon_y` and derives
  `text_y = icon_y + 6`. This preserves the exact invariant established by
  `text_y = (int)bonus_y + 1` and `icon_y = (int)bonus_y - 5`, while matching
  the native related row origins and its `icon_y - 12` panel calculation. The
  `popup-row-advance/advance-icon-derive-text` winner gained
  43.366571819165074 weighted bytes and removed five candidate instructions.
- Quest stage rollover now increments and stores the major stage before
  subtracting and storing the minor stage. Native `0x0041bf63..0x0041bf7d`
  has that order. The `quest-stage-rollover/increment-major-first` winner
  gained 11.665568369027824 weighted bytes and two aligned references.
- The ammo texture router now recovers the native explicit class-four branch,
  while retaining the same Electric-texture fallback for out-of-range values.
  Native `0x0041b6da..0x0041b72c` compares classes 1, 0, and 2, then executes
  `cmp eax, 4` at `0x0041b722` before binding the Electric texture. The old
  port omitted that test. `ammo-class-four/explicit-four-with-fallback` gained
  78.70472511983735 weighted bytes, four candidate instructions, and two
  aligned references; the dispatch mismatch regions disappeared.
- The quest-banner fade now preserves the native explicit 2,000--2,500 ms
  zero window. On the banner-only path, native `0x0041c079` compares the timer
  with `0x9c4` after the `< 2000` fade branch, then stores zero. The completed
  fade path at `0x0041c025` does not enter that block.
  `quest-banner-tail/explicit-2500-zero-window` gained
  13.824417938473744 weighted bytes and one candidate instruction.

These are source-recovery corrections supported by native branches and
statement order, not inert padding or register forcing. The retained
`scratch.cpp` SHA-256 is
`ee637eb004ded284c63b80e3b24ea9e70dd2e7fd87113be2244894c716be0782`.
The final score is 6,244.172196325747/7,081 weighted bytes
(`88.18206745270085%`), gap 836.8278036742531, 1,823/1,824 instructions,
prefix 42, and `390/0/0` references. Relative to the wave baseline, this is
+180.289520887151 weighted bytes, +2.54610254042015 percentage points, and
five additional aligned references.

All new sweeps were persisted to `experiments.jsonl`. Their spec SHA-256
values are:

| Spec | SHA-256 |
| --- | --- |
| `ammo-texture-dispatch-mutations.json` | `857ca1422164d17d4bf72541a8fed89f47e6e2a924f90bb1fcb9ce40ec883491` |
| `ammo-alpha-callsite-mutations.json` | `ca6c2af1e26b4c1413f10060a0e72c7595a0d4a053298782558da4da213a9c64` |
| `popup-row-origin-mutations.json` | `cf5d79a965245f421c27a906a00ee20ab4c4c3a860563ecc2a56a96e724b7014` |
| `popup-row-advance-mutations.json` | `6f8c053992cd1c7d91bba935679f0e19dd458ad6562e11944aaccda584c39a20` |
| `complete-fade-lifetime-mutations.json` | `fc3d62ac3d7ff6f930e07e86dd0767e2e0b1f0c19b4092fb3532006ec569b2b8` |
| `quest-stage-rollover-mutations.json` | `11d545067abd79ef45954edf266a9f01af660d0826af847309868bacf5bedecd` |
| `ammo-bar-local-lifetime-mutations.json` | `4b120625e5442ea77dbbdbed38cf0db2001583db9a5538ba4e985b9f111906e9` |
| `ammo-class-four-mutations.json` | `71a87d87562f0a56fd50b0e66fb18b48ef25f4bb16aa7aceb5ccf0691d13f1f6` |
| `quest-banner-tail-mutations.json` | `05d8a270b2d56e7af5f8fe80a6419c83a2e67d9b152a233c82a65c6850a79f19` |

Useful recorded negatives further narrow the compiler residual. Both switch
forms for the ammo router lost 31.05701754385973 weighted bytes and introduced
one mismatched reference; selected-name forms did not compile under VC6.5.
Complete-fade outer declarations and named deltas were neutral, while cached
timer forms lost 5.572873 weighted bytes and one reference. All four ammo-bar
local-lifetime variants were byte-neutral. At the final retained baseline,
all four popup-row-origin variants lose 7.766383328763368 weighted bytes and
one reference, so the remaining popup-origin difference is not improved by a
natural single-site lifetime spelling. The scratch remains
`semantic-complete` with only a `compiler` residual.

## Stage-label call evaluation and popup-scope bound (2026-07-29)

Native `0x0041bfc8..0x0041c01c` loads the renderer receiver and virtual call
target, leaves the stage-label Y expression live on x87, and then runs the
inlined `strlen` used to form X. A six-variant call-expression sweep recovered
that schedule by retaining the named `stage_x` calculation while inlining the
Y expression into `grim_draw_text_mono`. The conservative
`stage-label-call/named-x-inline-y` winner gains
7.766383328763368 weighted bytes with the same 1,823 candidate instructions,
42-instruction prefix, and `390/0/0` references. Three more fully inlined
spellings tie the byte result; the retained form keeps the recovered
native-backed X calculation explicit.

The final score is 6,251.93857965451/7,081 weighted bytes
(`88.29174664107485%`), gap 829.0614203454898, 1,823/1,824 instructions,
prefix 42, and `390/0/0` references. The prior stage-label structural
missing/extra pair disappears from the localized diff.

The adjacent popup-origin hypothesis is now independently bounded.
`popup-row-scope-mutations.json` evaluates six staged, direct, split, and
derived row-origin lifetimes. All six lose exactly 7.766383328763368 weighted
bytes and one aligned reference while preserving instruction count. No popup
scope source change is retained. The recorded spec SHA-256 values are
`0b61e5b25921a32ea8ad34a1f2b632d2f92e87fb5eb6df9c5342e0189bbf6827`
for the stage-label sweep and
`2b0ddc7c84308d1903c783fbee23ca839ae4b1c8fc3286e2bab0616b4ea60820`
for the popup-scope sweep.
