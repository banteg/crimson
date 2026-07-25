# creature_spawn_tinted

Exact match:

```txt
match=100.00% prefix=92/92 target_insns=92 candidate_insns=92 refs=34/0/0
```

The recovered source reconstructs the dedicated Typ-o creature initializer:
fixed health and reward, the chase-player AI mode, random heading and size, the
caller-provided RGBA tint, and the spider-specific speed, size, and flag
adjustments.

The source keeps the random size in a local because native retains that value
on x87 after storing the base size, then reuses it for the spider scale. The
spider path similarly computes a scaled-speed local before updating the flags
and storing both adjusted values. These are ordinary source temporaries that
account for the native instruction schedule without volatile accesses or
representation tricks.

This function also independently confirms that creature tint is runtime state,
not merely spawn-planning metadata: native copies all four caller-provided
components into the creature record before returning.

The recovered legacy declaration
`SpawnCreatureEx(vec2_t spot, color_t col, int type)` also identifies both
formerly raw pointer parameters as aggregates. The exact scratch and saved
Binary Ninja prototype now use read-only `vec2f_t` and `effect_color_t`
boundaries, exposing `pos->x`/`pos->y` and `color->r/g/b/a` without changing
the 92/92 instruction or 34/0/0 reference match. The shared gameplay header
now carries the same types, so its exact Typ-o caller passes the canonical
vector/color aggregates directly. Its one layout-equivalent local C++ vector
class keeps a narrow cast at that type boundary rather than degrading the
callee prototype to unrelated `float *` pointers.

The initializer now also copies those values through the canonical embedded
`creature_t::position` and `creature_t::color` aggregates. Both assignments
remain byte-for-byte exact, and the color copy no longer needs a duplicate
layout-only structure or pointer casts.
