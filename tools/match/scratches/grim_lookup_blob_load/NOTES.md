# grim_lookup_blob_load

`grim_lookup_blob_load` at `0x10005a40` opens an optional binary blob, measures
it with `fseek`/`ftell`, allocates `size + 1` bytes, reads one full item, closes
the file, and returns `true`. The extra byte is not explicitly terminated in
this function.

If the open fails, it clears `grim_lookup_blob_loaded`, conditionally deletes
the old buffer, clears the pointer, and returns `false`. That path is also used
by `grim_shutdown`, which passes the shared empty-string sentinel to force
cleanup.

The DLL calls the CRT through its import table. The scratch's explicit
`dllimport` declarations reproduce the target's dynamic-CRT build surface that
the bundled standalone VC6 headers do not select by default; they are ordinary
source-level linkage declarations, not masked or unreachable fakematching.

The recovered function matches all 51 instructions and all 15 references under
MSVC 6.5 `/O2 /GB`.
