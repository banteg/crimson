# vec2_length exact match

```txt
match=100.00% prefix=12/12 target_insns=12 candidate_insns=12 refs=0/0/0
```

The input is a read-only `vec2f_t`, recovering the native square-sum and
`fsqrt` kernel through named `x`/`y` components. The matching source and saved
Binary Ninja prototype produce the same exact 12-instruction body.
