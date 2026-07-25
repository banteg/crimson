# effect_defaults_reset

Exact match:

```txt
match=100.00% prefix=59/59 target_insns=59 candidate_insns=59 refs=29/0/0
```

This function restores the shared effect template defaults and rebuilds the
native `0x200`-entry pool's intrusive free list. Binary Ninja shows a
`0xbc`-byte entry stride from `effect_pool_pos_x @ 0x004ab330`, with the link
field at offset `0xb8`.

The native loop deliberately reaches entry 510 and then initializes entry 510
again in the explicit tail. The scratch preserves that oddity: stopping the
loop at 510 still produced the same normalized instructions, but the audited
compare operand pointed at entry 510 rather than the native entry-511 boundary.
Entry 510 is finally linked to entry 511, and entry 511 remains the zeroed
free-list terminator.

The otherwise-unreferenced words at `0x004ab268` and `0x004c2b34` are named as
reserved zeros rather than assigning unsupported counter semantics. The
two-float block at `0x004ab1b0` is likewise only claimed as the position/default
block that this function clears.

The shared template's zero velocity is now assigned through the canonical
`vec2f_t` / `effect_template_t::velocity` aggregate. This removes a
layout-equivalent cast while preserving the exact 59/59 body and all
29 references.
