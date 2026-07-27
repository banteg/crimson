# `quest_select_menu_update`

High-value recovery for the 3,436-byte quest-selection callback at
`0x00447d40`. This is the game-core Quest picker and state router, rather than
platform or rendering-backend glue.

## Recovered source shape

- derives the panel, title, five stage-icon, Hardcore-checkbox, ten-row list,
  and Back-button positions from UI element 37 with the native fixed offsets;
- constructs the complete eight-color palette, including the three colors
  retained only for native object-lifetime parity, and switches row idle/hover
  tints from blue to red while Hardcore is active;
- restores the fixed 32-by-32 stage hover rectangles, selected/unselected icon
  scale, mouse stage selection, and clamped Left/Right stage shortcuts;
- gates the Hardcore checkbox at quest unlock index 40 and forcibly clears it
  for the demo build;
- renders all ten locked/unlocked quest rows, title underlines, and the F1
  completed/games overlay. The play-count indexing intentionally preserves the
  native stage-five suffix alias documented by the modern port;
- accepts the 1 through 0 quick-select keys, mouse click, and Enter, applies the
  normal or Hardcore unlock table, and rejects the native sentinel row; and
- reproduces Back routing plus the successful quest-start transition: sign
  focus release, Quest game mode, three music mutes, selected stage copy,
  fade latch, pending Gameplay state, and UI click sound.

## Static-object evidence

The native constructor blocks use bits 1 through 128 of
`quest_select_menu_init_flags` for the row-idle, row-hover, unused-blue,
unused-dim-blue, title, selected-stage, hovered-stage, and unused-orange
colors. Bits 1 and 2 of `quest_select_screen_flags` guard the Hardcore checkbox
and Back button. PE disassembly registers the ten empty callbacks at
`0x00448b40` back through `0x00448ab0` in that construction order. The VC6
relocation table independently maps `$E2` through `$E9`, `$E11`, and `$E12` to
the same objects; `$E10` is skipped by VC6 when the second local-static guard
scope is introduced. Every named destructor scratch is an exact one-instruction
match.

## Matching evidence and honest residual

The verified VC6 build is 785 normalized instructions against 803 native,
scores 72.0403%, and audits 235 references as resolved, zero as unresolved,
and five as mismatched inside nonmatching instruction regions. Its weighted
gap is 960.6952 bytes. The broad behavior
and static-constructor sequence are recovered, but the natural reconstruction
uses a 56-byte frame while native uses 48 bytes. Native also keeps icon Y and
row/control constants in a different EBX/EBP/ESI allocation and lays out the
unlocked quest metadata block after its alternate unlock-table branch. Attempts
to collapse the named panel/position objects or force the decompiler-shaped
row labels reduced the match substantially, so those code-generation residuals
are recorded rather than hidden with match-only shaping.

The panel geometry now uses the recovered UI element and vertex position
aggregates in native operand order. Reordering the equivalent commutative
additions aligns the same four UI-element references without changing
behavior. Binary Ninja evidence around `0x004481cc` also shows that native adds
the selected icon's 64- and 16-pixel X offsets separately, rather than folding
them into 80. Expressing those two additions recovers the missing native
instruction and produces the small score improvement above.

The successful start path also retains the native selected-row dependency.
Disassembly at `0x00448a72..0x00448a8f` reloads
`quest_select_stage_minor_index`, increments that value, and stores it to
`quest_stage_minor`; it does not use only the equivalent local validation
copy. Expressing that dependency adds two honest candidate instructions and
slightly lowers the aggregate similarity, but recovers the native data flow
instead of preserving a scorer-friendlier local substitution.

## Bounded entry-order mutation evidence

Fresh mismatch regions and live Binary Ninja target
`3023:2:9499448411019345244` isolate the first residual to entry geometry and
stack layout. Native computes both base panel-coordinate sums before saving
EBX/EBP/ESI/EDI, spills the Y sum to `[esp+0x34]` at `0x00447d5f`, stores
`row_hovered = false` at `0x00447d63`, and only then applies the 300-pixel X
offset at `0x00447d68`. The candidate uses the same operands and values, but
has a 56-byte rather than 48-byte frame, stores the flag before spilling Y,
and colors that Y value at `[esp+0x24]`.

The schema-1 `row-hovered-init-order` sweep retained both named geometry
objects and the already-evidenced operand order. It tested only six real
declaration/initialization placements for the long-lived hover flag. The
persisted spec SHA-256 is
`9b5f94ad1375f61452383330711873d0363a49fca6bb7bbb41dda1a2b19ae981`;
the unchanged baseline source SHA-256 is
`d18ce2f4a736ae4670edc4fb028b1dae6a38780c85c2d40cbba9a0b793de3281`.
The complete harness ranking is:

| Rank | Placement | Source SHA-256 |
| ---: | --- | --- |
| 1 | entry initialized | `8e578f8facc95191485ba488518f3aa1baae1c4a2cc8c90a36e327b5e26cdae4` |
| 2 | entry declaration, assignment before panel offset | `738cddcc04efe587e270df5d7f8e37367cfb2814f9549ee8425a1e94b1d837bc` |
| 3 | split at the current position | `c9866c59cf6d6bbad2cd3179ff819280a9eb420fa1bdf51536d5950ac9cde313` |
| 4 | split before panel offset | `d4733a5cfc207d0b9c34b1d852109abf76c457fc3b881ce1b01618fbcc54b0e7` |
| 5 | initialized before panel offset | `f429b80bec17c4eeef53f0da85e86b8e119404038afb9095d2879a1fd842bef8` |
| 6 | initialized after position geometry | `7900dba61c3354a4040ae21692758eba5bf0449e83a8ebb01632aa6986400b2b` |

All six are byte-neutral: `71.15869017632241%`, 2,445.012594
fuzzy-weighted bytes, 785/803 instructions, prefix 0, `228/0/10`
references, and first target/candidate mismatch offsets `0/0`. The record has
`best_improves=false` and no winner. No positive single justified an
interaction sweep, and the semantic source remains unchanged.

## Position-copy lifetime correction

A follow-up pass combined the entry dataflow at `0x00447d5f..0x00447dbb`
with a live audit of the coherent selection-and-start tail at
`0x004487e8..0x00448aa5`. The tail confirms Back routing, mouse and 1-through-0
quick selection, Enter selection, unlock validation, and the successful
Gameplay/Quest transition already present in the source. At entry, native
forms and copies the working panel position with a lifetime consistent with
default construction followed by assignment; the previous source used copy
initialization.

The schema-1 `position-copy-shape` sweep tested four complete singles. Its
persisted spec SHA-256 is
`42a38329c1ba1fdbc848f06e19f1ed8a203956647fbbbb283432cae3049fee82`.
Default construction followed by `position = panel_position` is the only
positive result and is retained. The empty default constructor followed by
the implicit member assignment is semantically identical because both members
are assigned before use. Its source SHA-256 is
`b841f13bd49c4e41b95ff4b552672c7f8ea3d50d3a93e99274bb257dcb6a504e`.

The retained result moves from `2445.0125944584383/3436` weighted bytes
(`71.15869017632241%`) to `2475.304785894207/3436`
(`72.04030226700252%`): a gain of `30.292191435768473` weighted bytes and
`0.8816120906801062` percentage points. The gap falls from
`990.9874055415617` to `960.6952141057932`; instruction counts and prefix stay
785/803 and 0, while references improve from `228/0/10` to `235/0/5`.
Constructor-copy and both component-copy spellings regress to
`55.93434343434344%`, 781/803 instructions, and `202/0/15` references, so
they are rejected.

## Recovery classification

This scratch is `semantic-complete` with a `compiler` residual. A
fresh live Binary Ninja audit retains the complete stage-icon, Hardcore,
locked/unlocked row, Back, quick-select, validation, and gameplay-transition
paths, and its seven-call inventory agrees with the recovered source. All five
masked-reference mismatches occur inside nonmatching sequence alignments and
resolve to source operations already present in the surrounding native flow.
They remain visible and unaliased rather than being classified as separate
reference debt. The remaining 48-byte native versus 56-byte candidate frame
and register/lifetime differences are compiler layout, not missing menu
behavior.
