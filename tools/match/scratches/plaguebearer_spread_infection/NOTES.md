# plaguebearer_spread_infection

The recovered source preserves the native fixed-pool scan, strict 45-unit
distance test, first-hit return, and two-way infection propagation through
pool indices. The MSVC 6.5 `/O2 /GB` candidate matches all 64 instructions and
all 14 masked references.

Exact local score:

```txt
match=100.00% prefix=64/64 target_insns=64 candidate_insns=64 refs=14/0/0
```

Staging the squared length as `distance_sq = dx * dx` followed by
`distance_sq += dy * dy` recovers the native x87 schedule exactly. In
particular, VC6 now keeps both coordinate deltas on the FPU stack, squares the
x delta first, accumulates the y square, and discards the retained operand
around `fsqrt` exactly as native does.

The final control-flow evidence is a pre-tested `while` with an explicit
`found` exit. Since the creature pointer starts at the beginning of the fixed
pool, VC6 eliminates the initially known-true bound check, emits the native
single backward `jl`, and leaves the zero-return block directly before the
infection path. The previous `do`/`break` form required a redundant post-loop
comparison and three extra instructions.
