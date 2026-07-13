# effect_free

Exact match:

```txt
match=100.00% prefix=6/6 target_insns=6 candidate_insns=6 refs=2/0/0
```

The helper prepends one entry to the effect free list and clears its flags.
The exact `next_free` store at offset 0xb8 independently confirms the recovered
end of `effect_entry_t` and its 0xbc-byte stride.
