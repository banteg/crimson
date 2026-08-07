# `grim_pixel_format_destroy_dxt`

Native target: `grim.dll` at `0x10016c3c`, 160 bytes and 49 normalized
instructions.

The pinned DirectX 8.1 provider contains this body verbatim in
`obj\\i386\\cd3dxcodec.obj` as `??1CD3DXCodecDXT@@UAE@XZ`. The archive has
SHA-256
`39a8e21889a7c1f0b966f04a9e7d392de14ddebb3e091dfa1e5ce3e19564fc28`;
the matching member records compiler product 29, build 9178. Archive scanning
finds one unique 160-byte candidate for the target, and the ordinary scratch
reference audit proves the vtable, SEH prologue, deletes, and base destructor.

The destructor releases every per-block cache allocation when the cache is
active and its entry table is present. Cross-function reads in
`CD3DXCodecDXT::Fetch` and writes in its constructor identify the loop bounds
as integer `D3DBOX` coordinates: the inner loop walks `m_CacheBox.Top` through
`Bottom` in four-row blocks and the outer loop walks `Front` through `Back` by
slice. It advances one eight-byte cache entry per block, then releases the two
outer allocations at offsets `0x10b8` and `0x10c0` before the base codec
destructor runs.

The earlier source approximation reproduced the 49-instruction graph but
stopped at 75.51% because its compiler assigned the two loop registers in the
opposite order. The exact provenance-bound object supersedes that residual;
no inline assembly, dummy dependency, or fabricated relocation is used.
