# ui_get_element_index

## Plausibility pass (2026-09-25)

Pointer walks bounded by int-cast address compares were replaced with indexed `for` loops. C2's strength reduction and linear test replacement produce the same signed pointer compare. The source stays exact, byte for byte. See [the audit](../../PLAUSIBILITY-AUDIT-2026-09-25.md).
