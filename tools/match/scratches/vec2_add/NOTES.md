# vec2_add exact match

```txt
match=100.00% prefix=10/10 target_insns=10 candidate_insns=10 refs=0/0/0
```

Both operands are recovered as two-component aggregates. The source and saved
Binary Ninja prototype use a mutable `vec2f_t *dst` and read-only
`const vec2f_t *delta`, exposing `x`/`y` instead of four raw float accesses.
The function's integer zero return is also restored in Binary Ninja. These
type corrections preserve the exact native instruction stream.
