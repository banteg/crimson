# vec2_add_out exact match

```txt
match=100.00% prefix=9/9 target_insns=9 candidate_insns=9 refs=0/0/0
```

Native `0x0044ecf0` takes a two-float source through `ECX`, a destination
through `[ESP+4]`, and a right operand through `[ESP+8]`. It writes both
components, returns the destination in `EAX`, and ends with `ret 8`. The
matching source models this machine contract as an explicit output-pointer
member and uses named vector fields for the arithmetic.

The caller-emitted decorated symbol is a compiled-candidate symbol, not an
original-game symbol. The original executable has no COFF symbols or exports.
A VC6 member `operator+` returning a two-float object by value produces the
same 26 native bytes, using `[ESP+4]` as its hidden return buffer and
`[ESP+8]` as its right-hand reference. Ordinary composed callers can also be
byte-identical. See the
[reproducible contract controls](../../evidence/vector-return-contract-2026-09-08/README.md).

The saved Binary Ninja prototype now places `self` in `ECX` and types it and
the right operand as `vec2f_t`, replacing its former three-argument cdecl
interpretation. The returned destination stays `float *` as the current
explicit-output model, not as a uniquely proven original C++ return type.
The controls do not justify changing the canonical exact source or promoting
a shared vector class or translation unit.
