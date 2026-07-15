# bonus_apply

Current verified match:

```txt
match=100.00% prefix=668/668 target_insns=668 candidate_insns=668 refs=216/0/0
```

Native evidence:

- `bonus_apply` is at `0x00409890`, spans 2693 bytes, and contains 668
  instructions.
- The recovered source produces the full native instruction stream with all
  216 masked references proven equal.

Recovered source shape:

- The bonus dispatch is the observed compare chain rather than a jump table.
- Natural scoped locals reproduce the native 16-byte stack frame: two shared
  floats, scoped effect colors, and the Nuke impulse vector.
- Bonus Economist applies a `1.5f` duration multiplier.
- Reflex Boost refills clips and clears `reload_timer`; it does not clear the
  reload-active flag.
- Freeze and Nuke both scan all 384 creature records. Freeze emits eight shards
  plus a shatter effect for dead active creatures before deactivating them.
- Shock Chain and Fireblast derive projectile ownership from friendly-fire
  state. Shock Chain keeps natural `bonus_pos` and `target_pos` pointers, and
  both branches preserve native argument evaluation order with direct, inline
  angle expressions.
- Nuke emits its randomized projectile set, uses inclusive 256-unit axis
  gates, applies radial damage, and passes a two-float zero impulse.
- Every pickup except Nuke emits twelve trailing effects. Their native rotation
  scale is `0.049087387f` (2 pi / 128), not `0.02f`.

Port parity:

- Python and Zig already clear the Reflex Boost reload timer and already use
  the recovered `0.049087387f` burst rotation scale, so no port edit is needed.

Discarded variants:

- Artificial slot unions, volatile temporaries, and container/pointer tricks
  were useful probes but are not retained; natural scoped C++ expresses the
  matching stack and register lifetime.
