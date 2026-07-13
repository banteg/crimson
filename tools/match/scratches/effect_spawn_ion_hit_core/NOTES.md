# effect_spawn_ion_hit_core

Exact match:

```txt
match=100.00% prefix=32/32 target_insns=32 candidate_insns=32 refs=16/0/0
```

This helper configures the shared effect template for an ion impact ring and
passes it to `effect_spawn`. It uses effect id 1, flags
`0x19`, a blue-white `(0.6, 0.6, 0.9, 1.0)` tint, four-pixel half extents,
and zero rotation and velocity. The caller-provided lifetime is scaled by
`0.8`, while the scale rate is multiplied by `45.0`.

Assigning `flags` before copying the local color reproduces the native store
schedule. The local aggregate is ordinary source shape: MSVC materializes the
four color constants on the stack and then copies them to the shared template.
All three native callers ignore EAX, as do neighboring effect-only wrappers,
so the source prototype is conservatively modeled as `void`. The allocator
itself does return `effect_entry_t *`; its former `void *` type was generic.
