# `png_destroy_struct`

The native body is a unique exact match for
`obj\i386\pngmem.obj:?png_destroy_struct@D3DX@@YAXPAX@Z` in the pinned
DirectX 8.1 `d3dx8.lib`: it ignores null pointers and otherwise tail-jumps to
`free`.

The provider object records `@comp.id=0x001d23da` (product 29, build 9178).
The available `msvc7.0` profile reproduces the 13-byte body exactly and is used
only as the nearest compatible code-generation surrogate.
