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

The verified VC6 build is 784 normalized instructions against 803 native,
scores 71.08%, and audits 221 references as resolved, zero as unresolved, and
16 as mismatched inside nonmatching instruction regions. The broad behavior
and static-constructor sequence are recovered, but the natural reconstruction
uses a 56-byte frame while native uses 48 bytes. Native also keeps icon Y and
row/control constants in a different EBX/EBP/ESI allocation and lays out the
unlocked quest metadata block after its alternate unlock-table branch. Attempts
to collapse the named panel/position objects or force the decompiler-shaped
row labels reduced the match substantially, so those code-generation residuals
are recorded rather than hidden with match-only shaping.

The panel geometry now uses the recovered UI element and vertex position
aggregates.

The successful start path also retains the native selected-row dependency.
Disassembly at `0x00448a72..0x00448a8f` reloads
`quest_select_stage_minor_index`, increments that value, and stores it to
`quest_stage_minor`; it does not use only the equivalent local validation
copy. Expressing that dependency adds two honest candidate instructions and
slightly lowers the aggregate similarity, but recovers the native data flow
instead of preserving a scorer-friendlier local substitution.
