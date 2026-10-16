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

The function's observed eight-byte stack frame holds two explicitly written
zero words that are later read as velocity components. Its compiler-facing
overlay now names that float view as `vec2f_t zero_velocity` instead of
addressing anonymous parallel `int[2]` and `float[2]` arrays. A plain
initialized `vec2f_t` lets VC6 fold away the frame and seven instructions, so
the storage view is retained honestly. The named form remains exact at 92/92
instructions and 34/0/0 references.

## 1.9.8 (C2 9044), open (2026-10-16)

94.57%, two regions. 9044 sees the field stores as independent (all at one
height before the `crt_rand` call), so their order is IL order, while 8966
chains every store in source order.

- Velocity stores: 1.9.8 stores `vel_x` next to `vel_y` after `health`.
  Moving the `vel_x` assignment there reaches 95.65% under 9044 but breaks
  1.9.93 (8966 keeps source store order). What is left is `mov ecx, ebx`
  (the `vel_y` copy): it is ready at the `mov al, 1` cycle and outranks the
  `pos_y` store, where native issues the store first. All 121 single moves and
  800 random multi-moves of the setup assignments, early float locals for the
  velocity, `vel_y = vel_x`, swapped order and a `velocity` aggregate copy do
  not change that.
- Size block: the single-use `move_speed` local is forward-substituted by 9044
  past the flags read-modify-write (it separates the fields; 8966 does not),
  and the substitution's round takes the cycle native uses for the flags
  store. Dropping the local (`move_speed *= 1.2f` or a direct product) fixes
  1.9.8 and breaks 1.9.93; `float move_speed = ...; move_speed *= 1.2f;` and
  parenthesised products fix neither.

