# effect_spawn_plasma_hit_core

Exact match:

```txt
match=100.00% prefix=31/31 target_insns=31 candidate_insns=31 refs=15/0/0
```

The helper configures effect id 1 as a plasma impact ring: orange tint
`(0.9, 0.6, 0.3, 1.0)`, flags `0x19`, initial age `0.1`, caller-provided
lifetime, 4-unit half extents, and a scale step multiplied by 45. It clears
rotation and velocity before passing the template to `effect_spawn`.

The 16-byte local is a natural `effect_color_t` aggregate, matching the same
source shape recovered for the adjacent ion-hit helper. Setting the nonzero
age before copying lifetime is both semantically direct and required by the
native store order. No padding, volatile qualifier, dead branch, or other
code-generation-only construct is used.

The two native callers in `projectile_update` pass `(pos, 1.5f, 1.0f)` and
`(pos, 1.0f, 1.0f)`, respectively.

Both callers ignore EAX, as do neighboring effect-only wrappers, so the source
prototype is conservatively modeled as `void`; the retained allocator result
does not establish a pointer return on its own.

Both ports reproduce those calls and the helper constants. The Zig effect pool
also narrows spawn fields and every age update to `f32`. Python's `EffectPool`,
however, stores and accumulates Python doubles. At a float32 60 Hz timestep,
the native repeated dword stores reach age `0.9999997019767761` at the lifetime
boundary while the current Python path reaches `1.0000000469386578` and frees
this ring one update early. The Python effect pool should canonicalize spawn
state and arithmetic at the native float stores; trace-time rounding would only
hide the live-state divergence.
