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
