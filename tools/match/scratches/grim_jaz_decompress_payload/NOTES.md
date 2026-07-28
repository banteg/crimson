# grim_jaz_decompress_payload

Native target: `grim.dll` at `0x1000a880..0x1000a8c2` (66 bytes).

The version-1 JAZ envelope is:

1. one version byte,
2. a little-endian compressed byte count,
3. a little-endian unpacked byte count,
4. the zlib payload.

`unpack` writes the unpacked count to its output parameter and delegates the
allocation and expansion to another method on the same empty
`GrimJazDecodeScope` object. Preserving that instance-method relationship
keeps `this` live in `ecx`, which recovers the native `esi`/`edi` register
allocation. Declaring the output pointer after the size store recovers the
remaining stack-store order.

The VC6 `/O2 /GB /GX /MD` method is an exact 26-instruction match with its
callee reference resolved.

## Modeled translation unit

This scratch is the physical source provider for the contiguous
`grim-jaz-decode-island` at `0x1000a810..0x1000a8c2`. In native address and
COFF section order, the combined VC6 object emits:

1. `GrimJazDecodeScope::GrimJazDecodeScope`,
2. `grim_zlib_status_is_error`,
3. `GrimJazDecodeScope::decompress_alloc`,
4. `GrimJazDecodeScope::unpack`.

The native audit still compares every member independently against its
canonical isolated scratch. All four remain exact under the provider's shared
`/O2 /GB /W3 /GR- /GX /MD` profile, while the two intra-island calls become
object-local instead of external linker obligations.
