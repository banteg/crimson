# `effects_update`

Native target: `crimsonland.exe` at `0x0042e710` (267 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 85/85
normalized instructions, full prefix, and masked references `10/0/0`.

## Recovered source shape

- The signed induction variable becomes a pointer biased to `entry->age`; it
  walks all 512 `0xbc`-byte entries and compares against the one-past-end age
  address.
- `entry->age` is used directly after `+= frame_dt`. VC6 therefore stores the
  incremented value to the 32-bit field, spills and reloads that rounded value,
  and reuses it for the lifetime, zero, and alpha calculations. Introducing a
  separate source `age` temporary does not reproduce this sequence.
- Expiry is taken for `age >= lifetime`. Bit `0x80` queues a decal after
  overriding stored alpha to `0.8f`, or `0.35f` when bit `0x100` is also set;
  the entry is then returned to the free list.
- A non-expired entry moves only when its rounded age is non-negative. A local
  `dt` and two-component movement aggregate reproduce the native single load,
  x87 duplication, and two rounded position stores. Bits `0x4`, `0x8`, and
  `0x10` enable rotation, scale, and alpha updates respectively.

Binary Ninja confirms calls to `fx_queue_add` at `0x0042e77e` and
`effect_free` at `0x0042e78a`, plus callers at `0x0040ac0e` and `0x004459ff`.
The canonical `effect_pool` data-map alias lets the matcher prove both native
pool-offset references by address instead of accepting anonymous `ADDR`s.

## Port implications

Native has no non-positive-`dt` early return and no lifetime epsilon. More
importantly, every age and motion result is rounded through a 32-bit field
store. Both ports now preserve those rules: Python rounds age, movement,
rotation, scale, and alpha at the native stores, while Zig performs the same
`f32` updates without either guard. The focused lifetime regression keeps the
plasma-style boundary active through age `0.9999997019767761` and expires it on
the following update; zero-`dt` expiry and sub-epsilon lifetime cases cover the
two removed guards in both runtimes.
