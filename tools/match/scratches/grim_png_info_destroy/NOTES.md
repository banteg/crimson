# `png_info_destroy`

The native body is a unique exact match for
`obj\i386\png.obj:?png_info_destroy@D3DX@@YAXPAUpng_struct_def@1@PAUpng_info_struct@1@@Z`
in the pinned DirectX 8.1 `d3dx8.lib`. It clears the 64-byte info structure;
VC6 `/O1 /Oi` emits the exact native `rep stosd` sequence.

The archive object records `@comp.id=0x001d23da` (product 29, build 9178), so
the stock VC6 scratch is a byte-exact compatibility build rather than original
frontend provenance.
