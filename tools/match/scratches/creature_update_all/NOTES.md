# creature_update_all

Native target: `crimsonland.exe` at `0x00426220` (5,330 bytes).

This is the central 384-slot creature simulation sweep. Live Binary Ninja
disassembly and the Ghidra hotspot recovery establish the complete gameplay
shape: freeze gating, damage-over-time flags, target selection, all nine AI
modes, movement and spawner roots, animation, ranged and contact attacks,
perk interactions, infection, death motion, corpse effects, blood bursts, and
final body culling.

## Recovered source shape

- The two-player retarget path indexes the other player directly as
  `1 - current_player`; this reproduces the native subtract-from-player-two
  addressing and the long-lived loop-index spill.
- Linked AI modes use their live-link path as the native fallthrough, while
  dead links reset to orbit mode and the tethered variants apply 1,000 damage
  through fresh zero-vector temporaries.
- The phase angle deliberately performs separate `3.7` and pi multiplies,
  matching the two native x87 constants instead of folding them.
- Bounded spawner creatures and expired corpses are the native fallthrough
  arms. Reversing those high-level conditions recovers the large middle and
  tail control-flow blocks without layout-only gotos.
- Collision timer updates retain the freshly subtracted value, and heading
  updates add pi to the already-computed target heading. These ordinary local
  value shapes recover native x87 scheduling and constants.
- Damage and corpse-effect vector arguments use natural C++ temporaries bound
  by reference. VC6 therefore constructs the evidenced stack vectors at the
  call sites without fake references or dummy state.

## Remaining mismatch

The complete natural reconstruction is an honest 48.90% WIP: 1,292 candidate
instructions against 1,338 native instructions, with masked references
`206/0/5`. The residual is dominated by global register allocation: native
keeps the creature index in a scaled form and spills health, lifecycle, and
collision pointers into a `0x7c` frame, while VC6 coalesces the same source
values into a byte offset and a `0x64` frame. That changes repeated SIB
addressing, x87 cleanup, and alignment through the melee block. The five
reference mismatches are sequence-alignment artifacts over otherwise evidenced
player coordinates, constants, and perk calls; there are no unresolved
references. No volatile state, dead expression, inline assembly, register
constraint, fake alias, or artificial stack padding is used.
