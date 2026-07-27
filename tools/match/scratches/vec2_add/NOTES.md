# vec2_add exact match

```txt
match=100.00% prefix=10/10 target_insns=10 candidate_insns=10 refs=0/0/0
```

Both vector operands are recovered as two-component aggregates. The source
uses a mutable `vec2f_t *dst` and read-only `const vec2f_t *delta`, exposing
`x`/`y` instead of four raw float accesses. All four native callers also push a
third float mode (`0.0f`, `4.0f`, or `3.0f`); the helper does not read it. The
function's integer zero return and C linkage complete the cross-TU contract
while preserving the exact native instruction stream.
