# vec2_add_out exact match

```txt
match=100.00% prefix=9/9 target_insns=9 candidate_insns=9 refs=0/0/0
```

As with `vec2_sub`, the decorated symbol proves a `vec2_t` member with
`__thiscall`, two raw `float *` ABI parameters, and a `float *` return. The
source recovers the pointed-to pairs as vector aggregates without changing
that evidence-backed signature or the exact code.

The saved Binary Ninja prototype now places `self` in `ECX` and types it and
the right operand as `vec2f_t`, replacing its former three-argument cdecl
interpretation. The returned destination stays `float *` because the native
symbol explicitly encodes that type.
