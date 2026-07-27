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
