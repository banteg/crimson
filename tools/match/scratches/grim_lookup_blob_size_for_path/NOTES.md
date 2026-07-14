# grim_lookup_blob_size_for_path

`grim_lookup_blob_size_for_path` at `0x10005b80` is the size-returning sibling
of `grim_lookup_blob_find`. It skips the leading NUL-terminated `paq` magic,
then walks records containing a NUL-terminated path, a four-byte payload size,
and the payload bytes.

An exact path match returns the four-byte payload size. Nonmatches advance by
`strlen(path) + 1 + sizeof(size) + size`; an empty or exhausted table returns
zero. The caller uses the result as the byte count for both JAZ decode and
`D3DXCreateTextureFromFileInMemoryEx`.

The recovered source reproduces all 66 native instructions and all four
references under the default VC6.5 `/O2 /GB` profile. As with the pointer
helper, direct repeated use of `grim_lookup_blob` is material source evidence:
VC6 hoists the global into `ebx`, while a local alias produces a semantically
equivalent but only 95.45% candidate with the opposite commutative operand
choice. No register forcing or layout-only expression is used.
