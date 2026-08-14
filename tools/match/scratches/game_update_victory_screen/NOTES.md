# game_update_victory_screen

High-value recovery for the 1,883-byte final-quest completion screen at
`0x00406350`. Live Binary Ninja evidence identifies both message variants,
the complete navigation-button lifecycle, and all four destination actions.

## Recovered source shape

- renders the paused gameplay world and animated UI panel;
- constructs the text and button anchors from UI slot 35 geometry;
- renders the classic completion message and its Hardcore Splitter Gun reward
  variant with the native line spacing;
- lazily constructs the Survival, Rush, Typ'o'Shooter, and Main Menu buttons;
- updates the four vertically stacked buttons; and
- reproduces the native gameplay-mode, audio, fade, and menu transitions.

The two panel anchors use the native chained-vector expression
`position + vertex + (180, 40)`. VC6's temporary for the first addition
accounts naturally for the target's 24-byte frame and completes the exact
447-instruction match.

## Static-object evidence

The VC6 object relocations map `$E2` to the Survival button destructor at
`0x00406ae0`, `$E3` to Rush at `0x00406ad0`, `$E4` to Typ'o'Shooter at
`0x00406ac0`, and `$E5` to Main Menu at `0x00406ab0`. Live Binary Ninja
disassembly confirms that all four callbacks are single-instruction `ret`
thunks. The candidate matches all 447 instructions and all 189 references.

The function-local statics deliberately use ordinary C++ construction and
destruction so VC6 emits the native guard-byte and `atexit` lifecycle. No
volatile state, fake references, or register-shaping constructs are used.

Both chained panel expressions now name the recovered UI element and vertex
position aggregates; the function remains exact at 447/447 instructions and
189 resolved references.

## Original button constructor recovery (2026-08-14)

The recovered 2003 `gdiButton_t` constructor spells its adjacent force flags
as `forceSmall = forceBig = false`. The complete three-variant
`original-button-constructor-mutations.json` sweep maps that to
`force_small = force_wide = false` and keeps this function exact at 447/447
instructions with `189/0/0` references. Reversing the chain, or using separate
small-first stores, preserves the masked byte score but creates eight reference
mismatches, so neither was retained.

Source SHA-256 is
`64f52f26c9aeb420a5e9b32278921fcbb14c4d8ef3c3935d7a799eac53f49822`;
spec SHA-256 is
`76a16f9d972be8d6ce684316670cb98df682916a901b120ce589c63d204121fb`;
the experiment ledger SHA-256 is
`427055e984bb6d828a4dcbd948e222730fdcf2017593f53d1e718369ababda8b`.
