# plaguebearer_spread_infection

The recovered source preserves the native fixed-pool scan, strict 45-unit
distance test, first-hit return, and two-way infection propagation through
pool indices. All 14 masked references resolve to the intended pool fields and
constants.

Current best local score:

```txt
match=88.55% prefix=25/64 target_insns=64 candidate_insns=67 refs=14/0/0
```

Staging the squared length as `distance_sq = dx * dx` followed by
`distance_sq += dy * dy` recovers the native x87 schedule exactly. In
particular, VC6 now keeps both coordinate deltas on the FPU stack, squares the
x delta first, accumulates the y square, and discards the retained operand
around `fsqrt` exactly as native does.

The remaining mismatch is compiler control-flow shape, not a semantic
approximation. Native folds loop exhaustion into a single backward `jl` and a
zero-return fallthrough. The clean `do`/`break` source emits an inverted branch,
an extra jump, and a redundant post-loop comparison. Equivalent early-return,
infinite-loop, and explicit-found forms remove the redundant comparison but
move the zero-return block after the infection path. Keep this scratch WIP
until a plausible source abstraction explains the layout; do not force it with
assembly or artificial liveness.
