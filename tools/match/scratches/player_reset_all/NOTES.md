# player_reset_all

The recovered source matches the native reset semantics, field order, and C++
vector shape:

- exactly two native player slots are reset;
- spawn positions start at terrain center and alternate by `player_index * 80`
  on both axes;
- the player position is an embedded two-float vector assigned from a center
  temporary and adjusted through `operator+=` / `operator-=`;
- only the observed timers, weapon fields, perk counts, and reset-only words
  are cleared;
- the alternate pistol slot is initialized from weapon-table entry 1;
- the non-demo mouse position and every creature collision flag are reset
  inside the player loop.

The native immediate-zero store and its placement among neighboring gameplay
timers identify `player_reset_reserved_zero` as a write-only float, rather than
the earlier provisional integer view.

Current VC6 result: 91.83%, exact 94/127-instruction prefix, 127 target versus
130 candidate instructions, and references 57/0/1. The recovered vector
members reproduce the native 0x24-byte frame and the center, even-offset,
odd-offset, and mouse temporary slots exactly. The remaining tail is compiler
scheduling residue: candidate uses `AL` for the demo flag, then recomputes the
perk-array address after clobbering `EAX`; native keeps the player offset in
`EAX` and uses `CL`. Natural declaration, condition, and statement-order
variants either compile identically or disturb the otherwise exact prefix. Do
not add volatile, dead expressions, or register constraints to force it.
