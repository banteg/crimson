# `creatures_none_active`

## Plausibility pass (2026-09-25)

Pointer walks bounded by int-cast address compares were replaced with indexed `for` loops. C2's strength reduction and linear test replacement produce the same signed pointer compare. The source stays exact, byte for byte. Any older description below of the replaced spelling is historical. See [the audit](../../PLAUSIBILITY-AUDIT-2026-09-25.md).

The bounded pre-tested loop is exact with both the default `msvc6.5` profile and
VC6 SP6: 40/40 bytes, 12/12 instructions, and all four references align.

The earlier tail-tested spelling was exact only with the Processor Pack. Stock
VC6 peeled its first iteration, producing 15 instructions and a 44.44% match.
Making the already-required pool bound the loop condition recovers the native
CFG without changing behavior and removes the unsupported compiler override.
