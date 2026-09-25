# `bonus_reset_availability`

## Plausibility pass (2026-09-25)

Pointer walks bounded by int-cast address compares were replaced with indexed `for` loops. C2's strength reduction and linear test replacement produce the same signed pointer compare. The source stays exact, byte for byte. Any older description below of the replaced spelling is historical. See [the audit](../../PLAUSIBILITY-AUDIT-2026-09-25.md).

Exact 26-byte, 7-instruction match with MSVC 6.5 `/O2 /GB`; all three masked
references align.

The helper walks the `enabled` byte directly at the 20-byte
`bonus_meta_t` stride, enables all 15 metadata records, then disables
`BONUS_ID_NONE`. Its only live Binary Ninja caller is `gameplay_reset_state`
at `0x00412e78`, which ignores the incidental end pointer left in EAX. The
honest source signature is therefore `void`, not the decompiler's inferred
`char *` return.

Native xrefs show no other gameplay-time writes to these flags. The immutable
Python metadata already treats every real bonus as enabled and id zero as
disabled, so no runtime parity change is required.
