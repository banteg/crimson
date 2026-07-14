# grim_lookup_blob_find

`grim_lookup_blob_find` at `0x10005ae0` walks the blob loaded by
`grim_lookup_blob_load`. The first NUL-terminated string is the `paq` magic;
entries begin immediately after it.

Each entry is a NUL-terminated path followed by a four-byte payload size and
then the payload. Exact path matches return the payload pointer. Nonmatches
advance by `strlen(path) + 1 + sizeof(size) + size`, and malformed or exhausted
offsets return null.

The recovered source reproduces all 66 native instructions and all four
references. It remains an honest 95.45% WIP because VC6 chooses the opposite
base/index encoding for one commutative `LEA` and mutates the other addend in
the equivalent success-pointer expression. No register-forcing construct is
used.
