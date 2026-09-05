# perk_selection_screen_update

High-value recovery for the 1,347-byte perk-choice screen at `0x00405be0`.
Live Binary Ninja evidence identifies the complete choice-count policy, menu
layout, function-local static objects, cancel transition, and perk-application
tail.

## Recovered source shape

- renders the paused gameplay world and animated UI panel;
- builds the panel anchor with the native two-float `operator+` idiom and adds
  the `(180, 40)` layout offset through `operator+=`;
- draws the Pick a Perk banner and the Perk Expert/Perk Master sponsor text;
- selects five, six, or seven choices and preserves the native 19/18-pixel
  vertical spacing policy;
- keeps the Expert-dependent Y adjustment in branch-local scalar scopes, which
  preserves the native per-arm load and shared result store;
- lazily constructs the idle/hover colors and ten menu-item states;
- updates the hovered choice, draws its description, and constructs the unused
  Select button alongside the active Cancel button;
- handles the cancel transition; and
- applies the activated perk, decrements the pending count, and dirties the
  next generated choice list.

## Static-object evidence

The VC6 object relocation table proves the native local-static order and thunk
mapping: `$E2` is the idle color (`0x00406170`), `$E3` the hover color
(`0x00406160`), `$E4` the ten-item array (`0x00406150`), `$E5` the Cancel
button (`0x00406140`), and `$E6` the Select button (`0x00406130`). Live Binary
Ninja disassembly confirms that all five callbacks are single-instruction
empty destructor thunks. `REFERENCE_ALIASES` scopes the guard, objects, and
callbacks to those evidenced native identities.

## Remaining mismatch

The current source produces the same 314 normalized instructions and all 117
references align. It remains an honest 87.58% WIP because the native reserves
a 40-byte frame and coalesces the later Cancel-button position with a dead
two-float/spacing slot, while this natural VC6 reconstruction reserves 36
bytes and assigns that position a fresh slot. Direct scalar construction,
explicit vector copies, named field-value copies, and constructor variants
either retained that four-byte delta or worsened instruction order. No union,
volatile state, fake reference, or artificial register constraint is used to
force the native allocation.

The live Binary Ninja local listing independently confirms the native
40-byte frame and the overlapping two-float local roles. The remaining delta
is therefore classified as compiler allocation residue rather than missing
behavior.

The panel anchor now consumes the recovered `ui_element_t::pos` and
`ui_element_vertex_t::position` aggregates. This type-only cleanup preserves
the same 314 instructions and 117 resolved references.

## Expert-spacing branch scope

The native Expert-spacing branch compares the perk count before loading the
choice Y coordinate, performs the `+40` or `+50` operation inside the selected
arm, and publishes the result through one store at the join. Direct compound
assignments let VC6 hoist the common load and emit one store in each arm. Two
short-lived scalar temporaries, one scoped to each arm, recover the native
load/store shape without changing behavior, instruction count, or references.
This moves the score from 86.94% to 87.58%; the region is otherwise exact apart
from the known four-byte frame shift.

## Cancel-position lifetime audit

Live native and candidate disassembly confirms that the frame-size difference
is tied to the late Cancel-button vector. The native reserves `0x28` bytes and
reuses the dead line-height area at the call, while the canonical candidate
reserves `0x24` bytes and gives the vector a fresh pair of slots.

Three recorded mutation sweeps bound the ordinary source explanations:

- `button-position-lifetime-mutations.json` tests five declaration points and
  direct X/Y, reversed Y/X, and whole-vector publication. Its 23-case pilot has
  SHA-256 `d970eeadb63a83a9879a76fc76c49450f8459989c9d76776b9259db7936eb5ab`.
- `button-position-assignment-helper-mutations.json` expands that matrix with
  five reference/value/void assignment operators. All 143 possible one-, two-,
  and three-site variants were evaluated under SHA-256
  `ede14e0f87c670d80104a61f74a2b42f1481e7bb8094c2218914647693afa37b`.
- `button-position-special-member-mutations.json` evaluates 27 constructor,
  copy-constructor, and destructor interactions under SHA-256
  `5eab8f1aac58105acc00d8f20e17aee6f1c60fe638b21c9151c06e5e201c45c9`.

The only large apparent gain declares the vector early and assigns a temporary
value late. It reaches 93.35% and reproduces the native `0x28` frame, but emits
318 instructions against 314, drops reference agreement from `117/0/0` to
`115/0/1`, and copies the temporary through the wrong final stack pair. A
focused region comparison exposes all four extra instructions at the Cancel
call. Direct X/Y publication is byte-identical to the baseline; reversed
publication introduces two reference conflicts; explicit assignment helpers,
copy constructors, and zero-initializing defaults either erase the frame gain
or regress further.

The higher score is therefore a misleading stack-shift tradeoff rather than a
better reconstruction. The canonical 314-instruction, `117/0/0` source remains
unchanged, and the missing coalescing stays classified as compiler allocation
residue.

## Choice line height lifetime (2026-09-05)

The initial row spacing now starts at its first use, immediately before the
Perk Expert spacing branch. It is no longer live across the header and sponsor
calls. The three valid controls in `choice-line-height-lifetime-mutations.json`
include a full row scope and an anchor component copy; only the narrower
initialization lifetime improves native alignment. Moving the static choice
array to make the full-scope control well-formed introduces reference mismatches
and is rejected.

The retained source improves 87.579618% to 94.585987%, adding 94.375796
weighted bytes, while preserving 314/314 instructions. The prefix increases
from 0 to 15 and clean references improve from 117 to 119. Values, selection
logic, and callback order are unchanged. Opening temporary slots, the native
early line-height store, and the Cancel coordinate lifetime remain non-exact.
