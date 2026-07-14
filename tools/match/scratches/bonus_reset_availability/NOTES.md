# `bonus_reset_availability`

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
