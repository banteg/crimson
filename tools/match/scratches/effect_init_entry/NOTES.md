# effect_init_entry

Exact match:

```txt
match=100.00% prefix=36/36 target_insns=36 candidate_insns=36 refs=0/0/0
```

The recovered initializer establishes the render-entry defaults: inactive
flags and timers, unit scale and white tint, then four opaque-white vertices
with `zrhw = (0.5, 1.0)`.

The exact 0x1c loop stride and stores at vertex offsets 0x08, 0x0c, and 0x10
recover the underlying vertex shape as two 2D vectors (`pos`, `zrhw`), a packed
color, and a texture-coordinate vector. Four vertices end at offset 0xb8,
where the allocator stores the free-list link. Scoping the white color and
`zrhw` temporaries separately lets the compiler reuse the same 16-byte local,
which reproduces the native stack frame without volatile or dummy data.
