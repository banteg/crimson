# bonus_meta_entry_release

Native target: `crimsonland.exe` at `0x00412410` (36 bytes).

The routine is the natural destructor for the 20-byte bonus/perk metadata
record. It conditionally releases the owned `label` and `description` strings
in field order while leaving the scalar metadata untouched.

The VC6 C++ destructor matches all 16 instructions, full prefix, with both
native `crt_free` references aligned. No deleting-destructor flag, manual
`this` plumbing, or layout-only control flow is needed.

The authoritative name map now preserves the same
`bonus_meta_cpp_t * __thiscall` boundary. Replaying it no longer degrades the
destructor receiver to an unrelated `int *`, so both owned strings remain
named in native HLIL.
