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
- The Shock Chain and Nuke position aliases are recovered as read-only
  `vec2f_t` pointers, and the Nuke force temporary is a `vec2f_t` value. Named
  `x`/`y` fields replace the last seven raw component indexes without changing
  the exact 668/668 code or any of the 216 aligned references.
- Nuke's direct indexed projectile update uses the flat
  `projectile_t::fields.speed_scale` view. The compiler-facing record retains
  its nested interior-cursor overlay for scan-heavy functions, but ordinary
  gameplay source no longer spells this field as `pos.tail.vy.speed_scale`.
  The exact 668/668 result is byte-identical.
- Shock Chain sets `bonus_spawn_guard` at `0x00409da4` and unconditionally
  clears it at `0x00409e34`; Fireblast does the same at `0x00409e53` and
  `0x00409eb3`. These are literal resets rather than restoration of an incoming
  value.
- Nuke emits its randomized projectile set, uses inclusive 256-unit axis
  gates, applies radial damage, and passes a two-float zero impulse. Its native
  guard stores are likewise `1` at `0x0040a0f6` and `0` at `0x0040a1df`.
- Every pickup except Nuke emits twelve trailing effects. Their native rotation
  scale is `0.049087387f` (2 pi / 128), not `0.02f`.

Port parity:

- Python and Zig clear the Reflex Boost reload timer and use the recovered
  `0.049087387f` burst rotation scale. Both ports also preserve the native
  literal guard resets for Shock Chain, Fireblast, and Nuke; parity tests enter
  each path with the guard already set so restoring the incoming value fails.
- The Bonus Economist gate at `0x004098b2` calls the singleton
  `perk_count_get`, whose body at `0x0042fcf0` indexes player slot zero. Both
  ports now retain that co-op ownership in bug-compatible mode while corrected
  mode continues to use the player who collected the pickup.

Discarded variants:

- Artificial slot unions, volatile temporaries, and container/pointer tricks
  were useful probes but are not retained; natural scoped C++ expresses the
  matching stack and register lifetime.
- Binary Ninja still displays interior-pointer indexing in two compiler-chosen
  scans: Reflex Boost advances from `player_state_t::ammo`, and Freeze advances
  from `creature_t::pos_x`. Retyping either interior address as its enclosing
  struct would shift every field and be false, so those offsets remain
  explicitly identified rather than hidden behind an invalid type.

The Pyrokinetic radius test is different: it indexes owning creature and bonus
records, so its direct operands now use `creature_t::position` and
`bonus_entry_t::time.position`. This stronger source shape remains exact at
668/668 instructions and 216/0/0 references.
