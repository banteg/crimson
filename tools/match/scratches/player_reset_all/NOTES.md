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

## Recorded tail-lifetime search

`demo-flag-lifetime-mutations.json` records four byte, bool, and integer
lifetimes around the final player stores. All are byte-neutral, so naming the
native flag lifetime does not alter VC6's `AL` allocation.
`reset-index-lifetime-mutations.json` then tests carrying the cached player
index through the perk clear. Extending only its lexical scope is byte-neutral;
using it in the clear moves an earlier allocation boundary and regresses to
57.25%, so the narrower source remains retained.

`tail-scope-interactions.json` records 11 further one-, two-, and three-site
interactions between the demo-flag lifetime and perk-clear ownership (spec
`f32493907f89ecbdb76f84d30816b874823becbccd5815523cf75f9b2f5ceed5`).
Caching the flag or moving the clear inside the existing scope while retaining
the global index is byte-neutral. Reusing the scoped reset index disturbs the
earlier allocation boundary and regresses. Baseline remains **91.83%**,
130/127 instructions, prefix 94, references `57/0/1`.

## Death/demo control-shape follow-up

Live native instructions `0x0041fe3a..0x0041fe62` keep the demo flag in
`CL`, perform the final reset stores, compare it with zero, write
`death_timer = 16.0f`, and then reuse the still-live player offset in `EAX`
for the perk clear. The candidate's behaviorally equivalent schedule uses
`AL` and recomputes that offset.

`death-demo-control-shape-mutations.json` evaluated all eight equality-order,
empty-arm inversion, moved-write, and duplicated-write variants (spec
SHA-256
`6070aacbf928626c8625517504b16649a1ce58f23dec57aa8eefb74648958771`).
Equality and inverted-control spellings were byte-identical. Moving or
duplicating the death-timer write disturbed the exact prefix and regressed to
roughly 62.79%--64.34%, with only 34--35 aligned references and three or four
reference mismatches. No source change was retained. Final metrics remain
91.82879377431906%, a 47.719844357976626-byte fuzzy gap, 130/127
instructions, prefix 94, and `57/0/1` references. The final four-record
`experiments.jsonl` SHA-256 is
`48bb4d8731cba8cf4626b3e7409860c1b3126df9f5101ed72d159c8c7e877c7d`.

`perk-clear-owner-lifetime-mutations.json` tests whether a late typed
`player_state_t *` can keep native's already-scaled player offset live through
the demo branch and into the perk clear. An unused owner immediately before
the demo check is byte-neutral; using either late owner for the clear moves the
first mismatch from instruction 94 to 12 and falls below 51%, while owning the
final stores alone also regresses. The complete five-variant sweep is recorded
under spec SHA-256
`7f4b8c7bbb04fefbe95fa874acadc67d90b855e69b313e14f03ff4d32370fd1d`.
The native `EAX` reuse cannot be recovered by extending a narrow typed owner
without perturbing the otherwise exact prefix.

## Tail subobject and control interaction bound (2026-08-11)

Live Binary Ninja confirms that the native tail keeps the scaled player offset
in `EAX`, loads the demo byte into `CL`, copies the two mouse floats through
`ECX`, and reuses `EAX` for the perk-array `lea`. The candidate instead loads
the flag into `AL`, uses `EAX` for mouse X, and rebuilds the player offset from
the loop index before the same `rep stosd` clear. The apparent mouse reference
debt remains an alignment consequence of those register choices.

Three current-baseline sweeps test the remaining natural relationships:

- `perk-subobject-lifetime-mutations.json` carries only the typed perk array,
  rather than the whole player owner, across the demo branch in five pointer,
  `void *`, and array-reference forms. Every form disturbs the exact prefix and
  falls to 50.78%--60.08%.
- `mouse-position-copy-mutations.json` covers eight direct temporary, const,
  pointer/reference, destination-owner, and fixed-size `memcpy` copies. All
  eight are byte-identical to the 91.83% baseline.
- `cached-demo-death-interactions.json` combines the previously neutral early
  demo cache with the previously regressive post-branch death publication in
  six byte, bool, int, inverted, and duplicated-arm forms. Every interaction
  still moves the first mismatch from instruction 94 to 12 and falls to
  62.79%--64.34%.

These 19 variants leave no source-supported subobject, mouse-copy, or
demo/death interaction that preserves the exact prefix while selecting the
native `CL`/`EAX` allocation. Recorded spec SHA-256 values:
`a17d3112d9840acfa23d3135008a662f9a5ddd4d227ea9d8f4d97397506ced04`,
`95d5b22ab96e75233b8f6034198dce0a5d61ae6a4b3787c9baf2ed2808619e86`,
and
`72539289a4a3ad903354d91563078590943efdd380c3d0b4f67ab2b99f70da26`.
