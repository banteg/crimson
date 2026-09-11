# Spawn grid and dispatch recovery, 2026-09-11

The native `creature_spawn_template` (`0x00430af0`) creates one root and 27
children for each grid template `0x14..0x18`: nine columns at x offsets
`0, -64, ..., -512`, with three rows at y offsets `128, 192, 256`, in that
allocation order. Both runtime ports previously used a 16-unit vertical step,
creating 81 children and consuming 54 extra random draws per formation.

The C++ scratch already had the correct grid size, but attached the bronze-grid
`0x18` branch to the preceding dispatch ladder. Its final child then reached
the generic unhandled-template fallback: health became 20 instead of 260 and
an extra console call was made. Native `0x18` shares an `if / else if` ladder
with the following splitter and remaining templates, so it skips that fallback.
`recover.py` reconstructs exactly this branch attachment from `before.cpp`.
The native fallback for grids `0x14..0x17` is deliberately retained.

A direct port replay also exposed Python's randomized-heading calculation:
with seed 21, the heading roll is 292 and native PC24 stores
`2.919999837875366`, while multiplying by Python's double `0.01` produced
`2.92` (which rounds one float32 bit higher). Python now uses the existing
PC24 multiplication helper and the float32 literal, as Zig already did.

## Evidence and scope

- `verify.py` compiles the pinned before source and the reconstructed candidate
  with the scratch's unchanged VC6 profile, then executes both against the
  original PE under Unicorn 2.1.4. It verifies the PE digest, compiler layout,
  callee-saved registers, stack restoration, floating-point control word,
  instruction destinations and permitted writes.
- Both `creature_alloc_slot` and `creature_spawn_slot_alloc` execute their real
  native bodies. `crt_rand` is a shared explicit LCG or deterministic linear
  sequence model; `console_printf` and `effect_spawn_burst` record their
  arguments and return zero. Those callbacks overwrite volatile integer
  registers and flags. Their real effects and whole-game behavior are outside
  this proof.
- All 2,928 finite cases compare the entire 385-entry creature storage area
  (384 regular slots plus the declared overflow entry), all 32 spawn slots,
  the spawn/retry counters, return pointer, RNG state/draw count, and recorded
  call sequence. Cases cover template IDs 0 through 67, both x87 PC24/PC64
  modes, hardcore/retry settings, demo effects, fixed/random headings,
  previously occupied slots, last-slot/overflow allocation, full spawn-slot
  tables, every retry jump-table destination and the retry interval clamp.
- The recovered source has zero differences in those observations. The before
  source differs in state and calls in 78 bronze-grid cases. All 2,928 cases
  still have CPU write-order differences; their separate trace hashes are
  retained. This is not a whole-function byte or write-trace match.
- Deliberate 16-unit-stride and missing-last-row controls must be detected by
  both final state and random-draw checks. This independently checks the
  observations used to correct the runtime grid loops.
- `verify_ports.py` compares 100 PC24 native grid witnesses with the actual
  Python plan builder and the built Zig `spawn-plan` CLI. It checks counts,
  positions, target offsets, type, health, heading, links and RNG state with
  float32 bit comparisons. It additionally checks Python phase seeds; the
  Zig CLI omits those, so its dedicated runtime test checks them directly.
  This is a selected-field port comparison, not an assertion that every
  stored native byte has a corresponding port field. Skipped witness IDs and
  reasons are recorded: PC64 arithmetic is outside the runtime model, and
  negative retry counts are rejected by the Zig CLI.

Fresh before and after static results are both **88.89240506329114%**, with
3161 candidate / 3159 native instructions, prefix 23, and references 357/0/1.
The earlier 86.93% note was historical. This change claims behavior recovery,
not an increase in matching score or resolution of the remaining reference.
The receipts include uncovered instruction offsets; finite coverage is not
proof that unvisited branches are impossible or that further recovery is
exhausted.

## Reproduce

From the repository root, with local Unicorn JIT permission:

```sh
uv run --offline --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/spawn-grid-dispatch-2026-09-11/verify.py \
  --out /tmp/crimson-spawn-grid-proof
(cd crimson-zig && zig build -Doptimize=ReleaseFast)
uv run --no-sync python tools/match/evidence/spawn-grid-dispatch-2026-09-11/verify_ports.py \
  --native-results /tmp/crimson-spawn-grid-proof/results.json \
  --zig-binary crimson-zig/zig-out/bin/crimson-zig \
  --out /tmp/crimson-spawn-grid-ports.json
```

For pre-promotion review, the native verifier accepts `--candidate-source` and
requires that file to equal `recover.py`'s reconstruction. The JSON receipts
record sources, helpers, compiler files, matcher, harness, native image,
compiled object/body hashes, cases and bounded observations.
