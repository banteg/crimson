# sfx_release_all

## Plausibility pass (2026-09-25)

Pointer walks bounded by int-cast address compares were replaced with indexed `for` loops. C2's strength reduction and linear test replacement produce the same signed pointer compare. The source stays exact, byte for byte. Any older description below of the replaced spelling is historical. See [the audit](../../PLAUSIBILITY-AUDIT-2026-09-25.md).

Unless sound is disabled, releases all 128 resident SFX entries, writes the two
native shutdown messages, and flushes the console queue to `console.log`.

Exact 24/24-instruction match with all 13 native references aligned.
