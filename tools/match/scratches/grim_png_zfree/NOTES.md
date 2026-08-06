# `png_zfree`

The pinned DirectX 8.1 `d3dx8.lib` places `png_zfree` in
`obj\i386\png.obj` between the adjacent native `png_zalloc` and
`png_reset_crc` bodies. Its five-byte forwarding jump matches exactly and its
single relocation resolves to `png_free`.

The provider object records `@comp.id=0x001d23da` (product 29, build 9178).
The available `msvc7.0` profile is an exact code-generation surrogate for this
one-instruction body; it is not a claim that the provider used build 3077.
