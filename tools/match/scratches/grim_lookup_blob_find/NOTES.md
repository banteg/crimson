# grim_lookup_blob_find

`grim_lookup_blob_find` at `0x10005ae0` walks the blob loaded by
`grim_lookup_blob_load`. The first NUL-terminated string is the `paq` magic;
entries begin immediately after it.

Each entry is a NUL-terminated path followed by a four-byte payload size and
then the payload. Exact path matches return the payload pointer. Nonmatches
advance by `strlen(path) + 1 + sizeof(size) + size`, and malformed or exhausted
offsets return null.

The recovered source reproduces all 66 native instructions and all four
references. The final source-shape correction removes a local alias for
`grim_lookup_blob` and uses the global directly in each record expression.
VC6 hoists that repeated global into `ebx`, exactly reproducing the native
base/index choice and destructive success-tail addition without any
register-forcing construct.
