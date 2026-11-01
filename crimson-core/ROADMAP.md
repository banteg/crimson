# Roadmap

Open work on the core and the clients' evidence. What the core does today is
in the [README](README.md), the clients in [PORT.md](PORT.md); client releases
(a Windows host, signed builds) are in the
[feature matrix](../docs/rewrite/feature-matrix.md#next).

## Gate coverage

- Use the [quest outcome table](results/quest-outcomes.md) to choose the next
  successful late-stage traces, particularly under the original bug policy
  and the 1.9.8 rules. It records clears, deaths and incomplete runs separately.
- Fixes still only partly exercised by the corpus: Shock Chain or a seeker with
  no creature left (20), a bonus carrier's death handled twice (33), and an
  exact-zero Highlander hit (18). Each needs a bot scenario that reaches it
  under both policies.
- The Python port checks the historical Typ-o run and its checkpoints. Adding
  Typ-o to the recovered verifier would allow the same cross-port comparison.

## Client checks

The [session tests](PORT.md#evidence) compare recordings with continuous and
interrupted audio. The packaged browser check records a run, reloads and
watches it from the local score. Profile tests cover restore and failed storage
operations.

- Repeat the audio and persistence scenarios on physical devices and other browser engines.
- Compare captures against the original for terrain, corpse and decal bakes,
  alpha thresholds, blend factors, write masks, fonts, texture edges and gamma.
  Record acceptable differences for each scene.

## Floating-point state and hash behavior

The [WASM specification](https://webassembly.github.io/spec/core/exec/numerics.html#aux-nans)
allows variation in NaN signs and, for noncanonical operands, payloads outside
its deterministic profile. Running the same module in V8 and Wasmtime does not
alone guarantee identical raw NaN bits. Do not rely on an engine-specific
canonicalization setting for a browser/Workers contract.

Inventory non-finite values in the authoritative schema during the full-run
and bot gate. Reject non-finite input as today, and make an unexpected
non-finite value in a field required to be finite a deterministic simulation
error. If an intentional NaN sentinel is needed, define its bit representation
at the producing boundary and in snapshot/hash serialization. Ensure payload
bits never influence gameplay via integer reinterpretation. Canonicalizing
only a hash must not conceal invalid authoritative state.

## Grow the original-code differential

Grow this alongside concrete full-run discrepancies; a differential harness for
every translation unit is not a prerequisite. Start with stateful player,
projectile, creature, perk and bonus routines using states sampled from Rush,
Survival and quest runs. The math oracle demonstrates direct calls into the
original x87 code without substituting the Python implementation for
Normalize.

Use `NativeOracle.trace_memory()` for original read/write sets and compare
canonical written fields and RNG against the compiled functions. `data.py`
provides symbol locations, but a global image cannot simply be copied: native
64-bit pool strides differ, and even wasm32 pointers, function addresses and
heap references need relocation. Add typed state/argument serialization and
explicit dependency/environment contracts. Expand snapshot coverage where a
routine reads state absent from the current diagnostic schema.

Track tested routines, states and branches, not only translation units; a unit
can contain multiple functions and helpers. Then grow toward the full
orchestration, including initialization and the selected modern session policy.

## Retire generated adaptations deliberately

The current hash/count guards are appropriate for now. They are not the
long-term maintenance model. Move proven numerical operations and input seams
into named source abstractions that preserve the historical compiler's exact
expansion while providing modern implementations. A generic `X87_WIDE` cast
alone is insufficient: first-operation rounding, exponent range, F32 spills and
CRT helper behavior are separate properties.

Gate that migration on actual historical compiler/object matching and the
original-code differential for each affected target. Keep adaptations for
different original versions explicit. Do the source migration after the
correctness contracts are established, without turning the adapter into another
independent simulation implementation.

Keep one pinned implementation of the portable numerical helpers owned by the
recovered core, with original x87 oracle cases as its regression contract; the
CRT power model is duplicated today in [`host/math.c`](host/math.c) and
Python's `crimson.math_parity`.
