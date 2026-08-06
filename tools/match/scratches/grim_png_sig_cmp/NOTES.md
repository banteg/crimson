# `png_sig_cmp`

The 72-byte native body is a unique exact match for
`obj\i386\png.obj:?png_sig_cmp@D3DX@@YAHPAEII@Z` in the pinned DirectX 8.1
archive. It bounds both the start and length to the eight-byte PNG signature,
then performs the native intrinsic byte comparison against
`grim_png_signature` at `0x1004e51c`.

The provider object records `@comp.id=0x001d23da` (product 29, build 9178);
the local MSVC 7 profile is a byte-exact code-generation surrogate.
