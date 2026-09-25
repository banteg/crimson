# audio_suspend_channels

## Plausibility pass (2026-09-25)

Pointer walks bounded by int-cast address compares were replaced with indexed `for` loops. C2's strength reduction and linear test replacement produce the same signed pointer compare. The source stays exact, byte for byte. Any older description below of the replaced spelling is historical. See [the audit](../../PLAUSIBILITY-AUDIT-2026-09-25.md).

Stops all 128 music entries only when audio is active and both sound and music
are enabled.

Exact 19/19-instruction match with all six native references aligned.
