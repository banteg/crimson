# Roadmap

Open work on the core and the clients' evidence. What the core does today is
in the [README](README.md), the clients in [PORT.md](PORT.md); client releases
(a Windows host, signed builds) are in the
[feature matrix](../docs/rewrite/feature-matrix.md#next).

## Gate coverage

- Report bot quest completion and failure coverage separately in
  [`results/gate.json`](results/gate.json). Runs that exhaust their budget are
  incomplete, not terminal coverage.
- Fixes still only partly exercised by the corpus: Shock Chain or a seeker with
  no creature left (20), a bonus carrier's death handled twice (33), and an
  exact-zero Highlander hit (18). Each needs a bot scenario that reaches it
  under both policies.
- Typ-o: the gate's Typ-o fixture is unsupported.

## Client checks

The simulation and session checks in [PORT.md](PORT.md#evidence) have no
counterpart yet for:

- **Audio**: identical results with real audio, a null sink, muting, an
  autoplay lock, voice saturation and device failure.
- **Graphics**: captures against the original of terrain persistence, corpse
  and decal bakes, the alpha threshold, blend factors, write masks, fonts,
  texture edges and gamma, with documented tolerances.
- **Persistence**: saves survive relaunch and reload; a failed asset or storage
  operation is visible and never changes a ranked run's setup.

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
