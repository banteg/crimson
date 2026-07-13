# grim_get_config_var

Native target: `grim.dll` at `0x10006c30` (102 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 32/32
normalized instructions, full prefix, and masked references `5/0/0`.

## Recovered source shape

- The prior `void (unsigned int *out, int id)` prototype exposed MSVC's
  hidden structure-return buffer as an ordinary argument. Callers push a
  16-byte destination and the ID, then immediately read through the pointer
  returned in `EAX`.
- The logical C++ method returns a four-dword `grim_config_value_t` by value.
  IDs `0..127` select a record from `grim_config_values`; all other IDs return
  the zero-filled `grim_config_default` record.
- The record shape naturally reproduces the native `ESI` save around the
  four-dword copy, `retn 8`, and all four base-plus-offset fallback reads.

No inline assembly, volatile state, dummy references, ABI shim, fake type, or
layout-only expression is used.
