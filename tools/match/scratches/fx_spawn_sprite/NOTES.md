# fx_spawn_sprite exact match

```txt
match=100.00% prefix=48/48 target_insns=48 candidate_insns=48 refs=16/0/0
```

The fixed-pool constructor takes read-only position and velocity vectors.
Matching source and saved Binary Ninja prototypes now expose both pairs through
`x`/`y`, replacing four raw float indexes while preserving every native byte
and reference.
