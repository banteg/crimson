# vec2_sub exact match

```txt
match=100.00% prefix=9/9 target_insns=9 candidate_insns=9 refs=0/0/0
```

Native `0x00417640` takes a two-float source through `ECX`, a destination
through `[ESP+4]`, and a right operand through `[ESP+8]`. It writes both
components, returns the destination in `EAX`, and ends with `ret 8`. The
matching source models this machine contract as an explicit output-pointer
member and uses named vector fields for the arithmetic.

That source signature is not uniquely recovered. The decorated symbol in
`scratch.conf` belongs to the compiled candidate; the original executable has
no COFF symbols or exports. A VC6 member `operator-` returning a two-float
object by value produces the same 26 native bytes: its hidden return buffer
occupies the destination slot and its right-hand reference occupies the other
slot. Ordinary composed callers can also be byte-identical. See the
[reproducible contract controls](../../evidence/vector-return-contract-2026-09-08/README.md).

Binary Ninja now has the recovered `__thiscall` convention and a typed
`vec2f_t *self`; it previously misrepresented `this` as a third cdecl stack
argument. `self` and the read-only right operand render through `x`/`y`.
The destination remains a `float *` in the final HLIL assignment as the
current explicit-output model. It is not evidence of an original C++ return
type. The controls do not justify changing the canonical exact source or
promoting a shared vector class or translation unit.
