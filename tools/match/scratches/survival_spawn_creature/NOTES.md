# survival_spawn_creature

High-value recovery for the 1,973-byte survival-mode random creature builder
at `0x00407510`.

The source follows the live Binary Ninja evidence from allocation through final
color clamping: experience-tier type selection, randomized base size/heading,
type-specific speed and health, experience-driven tint ramps, three rare color
variants, two rarer boss variants, and final health/reward/color normalization.

The exact VC6 shape revealed two aggregate members that the current flat ABI
header does not preserve: a two-float velocity and a four-float RGBA tint. The
temporary constructors and final tint pointer are source-level object
operations, not scheduling constraints. Ordinary signed `%` expressions also
recover the native negative-remainder correction for the two-way type roll.

Focused result: **100.00%**, 517/517 instructions and 85/0/0 references. The
anti-fakematch validator passes; there are no volatile operations, synthetic
references, dead expressions, or register-forcing constructs.
