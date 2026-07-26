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

The corresponding Python and Zig gameplay reset now mutate existing player
records rather than replacing the whole object. This preserves native
unwritten residue, including the primary `reload_active` byte, Fire Bullets and
perk-effect timers, movement phase, aim state, and muzzle-flash state. The
ports still apply the represented `gameplay_reset_state` follow-up writes
(`low_health_timer`, Python `auto_target`, and the separate player auxiliary
timer). Zig first-use storage is initialized explicitly before the partial
reset, so the parity fix does not read undefined stack data.

The native immediate-zero store and its placement among neighboring gameplay
timers identify `player_reset_reserved_zero` as a write-only float, rather than
the earlier provisional integer view.

The scratch now uses the canonical recovered `player_state_t` directly for
`plaguebearer_active`, position, health, `state_aux`, and the two bonus timers.
This removes the former 0x360-byte local padding mirror; the only cast left at
the position boundary is the native two-float vector operation over the
canonical `position` aggregate. Binary Ninja independently resolves the same
stores to those named `player_state_t` fields. This type-only cleanup preserves
the result below byte-for-byte.

Current VC6 result: 91.83%, exact 94/127-instruction prefix, 127 target versus
130 candidate instructions, and references 57/0/1. The recovered vector
members reproduce the native 0x24-byte frame and the center, even-offset,
odd-offset, and mouse temporary slots exactly. The remaining tail is compiler
scheduling residue: candidate uses `AL` for the demo flag, then recomputes the
perk-array address after clobbering `EAX`; native keeps the player offset in
`EAX` and uses `CL`. Natural declaration, condition, and statement-order
variants either compile identically or disturb the otherwise exact prefix. Do
not add volatile, dead expressions, or register constraints to force it.

## Recovery classification and reference re-audit

The recovered reset policy accounts for every native write and both fixed
player iterations. The focused tail delta is the documented `AL`/`CL`
allocation and three extra address-recomputation instructions.

The sole reported reference mismatch is diff alignment, not an incorrect
global. Native writes mouse X to `ui_mouse_x` at `0x0041fe78` and mouse Y to
`ui_mouse_x+4` at `0x0041fe82`. The candidate object writes the same pair at
offsets `+0x1fb` and `+0x200`. The differing temporary-register schedule
leaves the common `mov [ADDR], ecx` shape on opposite components, so
SequenceMatcher pairs native X with candidate Y and reports 57/0/1 even
though both real operands resolve to the correct adjacent fields.

Classification is `RECOVERY=semantic-complete`, `RESIDUAL=compiler`. The
classification is byte-neutral: before and after are 91.83%, prefix 94/127,
130 candidate versus 127 target instructions, and references 57/0/1.
