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

The selected object also emits the true `perk_meta_cpp_t` destructor identity.
Native xrefs from both perk array helpers at `0x0042faa0` and `0x0042faf0`
resolve to this same implementation at `0x00412410`; both 20-byte record types
own two string pointers in the same order. The two natural destructor bodies
therefore give the linker both decorated class identities while retaining the
configured bonus destructor at 16/16 instructions and `2/0/0` references.
