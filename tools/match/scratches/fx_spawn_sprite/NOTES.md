# fx_spawn_sprite exact match

## Plausibility pass (2026-09-25)

Pointer walks bounded by int-cast address compares were replaced with indexed `for` loops. C2's strength reduction and linear test replacement produce the same signed pointer compare. The source stays exact, byte for byte. Any older description below of the replaced spelling is historical. See [the audit](../../PLAUSIBILITY-AUDIT-2026-09-25.md).

```txt
match=100.00% prefix=48/48 target_insns=48 candidate_insns=48 refs=16/0/0
```

The fixed-pool constructor takes read-only position and velocity vectors.
Matching source and saved Binary Ninja prototypes now expose both pairs through
`x`/`y`, replacing four raw float indexes while preserving every native byte
and reference.

The destination record now receives both values through its canonical
`sprite_effect_t::position` and `sprite_effect_t::velocity` aggregates. These
two aggregate assignments remain byte-for-byte exact.
