# `grim_yuv_cache_entry_init`

Native target: `grim.dll` at `0x1000ae4f`, three bytes.

Binary Ninja shows the complete body as `mov eax, ecx; ret`. The function is
an empty default constructor for a 16-byte YUV channel-cache entry: callers
pass the entry in `ECX`, and the constructor returns that same pointer in
`EAX`. The `__fastcall` spelling preserves that this-like register ABI without
inventing any state changes.
