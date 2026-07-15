# `mod_load_info`

Native target: `crimsonland.exe` at `0x0040e700` (332 bytes).

Live Binary Ninja evidence shows the CMOD metadata load path and explains the
native local-static initialization sequence. The function builds `mods\\%s` in
a 512-byte stack buffer, loads the DLL, resolves `CMOD_GetInfo`, copies the
returned 0x48-byte block, unloads the enumeration-only module, and returns the
stable local copy.

The metadata object is a function-local C++ static with two 32-byte strings,
default version `1.0`, API version `3`, and an empty destructor registered with
`atexit`. That source shape accounts for the shared guard byte, the two eight-
dword zeroing loops, and the 18-dword copy in the native routine.

The scratch-scoped `info`, `$S1`, and `$E2` mappings bind the compiler-local
object, guard, and destructor symbols to their uniquely evidenced native
counterparts. They preserve full masked-reference auditing rather than hiding
or weakening it.

No dummy references, inline assembly, volatile ordering constraints, or dead
expressions are used.
