# player_find_in_radius WIP

Current best local score:

```txt
match=77.06% prefix=9/54 target_insns=54 candidate_insns=55 refs=4/0/1
```

The scratch preserves the owner-derived skip index, configured player-count
bound, alive-player filter, radius-plus-size test, and first-hit return.
Staging `distance_sq` as the x square followed by the y-square accumulation
recovers the native x87 distance kernel exactly.

The remaining differences are backend shape. Native keeps the loop pointer
based at `health`, while VC6 rebases the equivalent source pointer at `pos_y`;
native also places the miss return on the loop fallthrough, whereas the clean
early-return source emits an inverted loop branch and keeps the hit epilogue
before the miss epilogue. Do not force either difference with raw offsets or
layout-only gotos.
