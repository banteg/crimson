# vec2_sub exact match

```txt
match=100.00% prefix=9/9 target_insns=9 candidate_insns=9 refs=0/0/0
```

The decorated MSVC symbol proves this is a `vec2_t` member using `__thiscall`
with two `float *` parameters and a `float *` return. The matching source keeps
that ABI honestly, then interprets both pointed-to pairs as vectors so the
component arithmetic uses named fields.

Binary Ninja now has the recovered `__thiscall` convention and a typed
`vec2f_t *self`; it previously misrepresented `this` as a third cdecl stack
argument. `self` and the read-only right operand render through `x`/`y`.
The destination remains a `float *` in the final HLIL assignment because that
is the native symbol's actual return type, not an unrecovered offset.
