# `ui_update_notice_update`

Native target: `crimsonland.exe` at `0x00442150` (614 bytes).

Live Binary Ninja evidence recovers the update-available panel, explanatory
text, function-local button state, and request flag.

Exact verified match: 100.00%, with 156/156 normalized instructions and
masked references `47/0/0`, using Microsoft Visual C++ 6.5 with
`/O2 /GB /W3 /GR-`.

## Recovered source shape

- The panel uses a black fill at 80% of the caller alpha, followed by a white
  outline and the caller alpha for its border state.
- The red `NOTE:` label and four small-text lines reproduce the native
  coordinates and colors. The two blank lines use the executable's shared
  empty-string object.
- An ordinary function-local static button owns `Get the update`. Its default
  constructor enables it, clears both animation counters and interaction
  flags, and sets alpha to one; VC6 registers its empty destructor at exit.
- The button sits at `(x + 65, y + 40)`. Activating it sets the global request
  flag consumed by the platform update-opening path.

The static button object and its one-byte constructor guard were previously
unnamed. Their data-map identities and compiler-local aliases are now recorded
so the exact instruction match retains a strict reference audit.

## Original button constructor recovery (2026-08-14)

The recovered 2003 `gdiButton_t` constructor spells its adjacent force flags
as `forceSmall = forceBig = false`. The complete three-variant
`original-button-constructor-mutations.json` sweep maps that to
`force_small = force_wide = false` and keeps this function exact at 156/156
instructions with `47/0/0` references. Reversing the chain, or using separate
small-first stores, preserves the masked byte score but creates two reference
mismatches, so neither was retained.

Source SHA-256 is
`e6fc590271a049e6453b24af1b9cd142ac7eb4a3f013d3b810c9a7662b291141`;
spec SHA-256 is
`76a16f9d972be8d6ce684316670cb98df682916a901b120ce589c63d204121fb`;
the experiment ledger SHA-256 is
`5561c8d20f66f566ba018cea4a6657c1abe85a3ef548401923c94369a6eb3566`.
