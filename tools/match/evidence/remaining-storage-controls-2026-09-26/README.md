# Remaining storage controls, 2026-09-26

The compiler's typed-copy behavior resolves projectile_render's K2 zero-alpha
temporary. The retained source uses the same alpha wrapper and tint constructor
already present in `player_render_overlays`: the constructor assigns a four-byte
alpha object, instead of assigning its float member directly. No compiler,
matcher, shared header, or reference alias was changed.

Baseline: `b8753fa7725ae247208445a48e0388e4667a256a`, stock `msvc6.5`,
`/O2 /GB /W3 /GR-`. [controls.json](controls.json) pins the image, compiler,
source/config hashes, exact source edits, normalized whole-COFF hashes, and
results for all 34 controls (13 player, 21 projectile, including both baselines).

| projectile_render | Baseline | Retained tint copy |
| --- | ---: | ---: |
| Raw similarity | 94.232681% | 97.746852% |
| Branch labels masked | 99.204508% | 99.403579% |
| Candidate instructions | 3013 | 3015 |
| Matching prefix | 195 | 1322 |
| References, matched/unresolved/mismatched | 544/0/0 | 544/0/0 |
| Frame bytes | 412 | 412 |
| Normalized exact / encoded body exact | false / false | false / false |

Most of the raw gain is downstream branch-offset repair. This is a partial
recovery, with no new whole-function exact match or linked credit.
[renderer-residual.json](renderer-residual.json) records the seven remaining
regions, beginning with the arc updates at `0x424cd0`.
[regressions.json](regressions.json) compares the native manifests with the
pinned baseline: this renderer is the only changed function, with no errors
or regressions. The corpus checkpoint retains 807/810 normalized matches;
both images' native artifacts are current. The two Crimsonland structural-link
integration tests and all eleven regression tests pass.

## Why the copy survives

The decompiled compiler and [post-promotion-stores.md, section 5](../../c2/compiler/post-promotion-stores.md#5-player_render_overlays-plain-source)
explain the source choice. A float store (type `0x4004`) and an unsigned scalar
copy (type `0x2004`) expose overlapping views of one four-byte object. Promotion
marks the unsigned read while leaving the float store in memory; live-range
construction restores the read to memory. The final code loads the stored zero
into `esi` and reuses it for the two alpha arguments.

[tint-store-trace.txt](tint-store-trace.txt) observes that lifecycle in the
retained source. The unnamed temporary is `#3469`, its float view is `#3472`,
and the destination views are `#274` and `#275`. The trace already contains the
scalarized `0x15b` copy at the first recorded optimizer-exit boundary. This
is not evidence that a late opaque `0x190` intrinsic caused this particular
store. [c2-tint-manifest.json](c2-tint-manifest.json) records whole-COFF equality
apart from its timestamp, missing-stream rejection, and unmodified compiler
decisions. The literal four-byte memcpy control has the same observed
store/promotion/demotion lifecycle; its manifest and trace are included too.

Scalar initialization and direct float copies fold the zero. `memset` and
integer-union zero initialization get a register zero without the native
store/load. A four-byte aggregate copy or literal memcpy recovers K2; the
existing tint-constructor pattern also preserves the broader source shape and
gives the best measured score. Both tint constructor spellings tie. These are
bounded controls, not a claim that the original type names are recovered.

## Byte and execution checks

[region-receipt.json](region-receipt.json) checks all 76 bytes at native
`0x422f95..0x422fe1` (18 instructions). Only the two four-byte DIR32 fields
are masked, after verifying their exact `grim_interface_ptr` identity, native
address, relocation type, and zero addend. Corrupting the alpha, load slot, or
reference identity is rejected.

[execution-receipts.json](execution-receipts.json) records 13,034 finite fixture
cases and 12 callback cases against the original function:

| Fixture group | Cases |
| --- | ---: |
| Plasma head, beam, ion chain, laser owner, secondary body | 2696 |
| Conventional corner rounding | 4118 |
| Laser trigonometric rounding | 5040 |
| Position boundaries | 656 |
| Ion endpoint rounding | 524 |
| Callback mutations | 12 |

Call traces and the modeled state checks agree. A deliberate `0.25f` alpha
changes exactly the two color-slot calls, so the new negative control detects
the behavior affected by this change. The historical replay's old negative
control referred to a source expression that no longer exists; its fixture
oracle and immutable receipts remain unchanged. The new verifier replaces that
source-text assertion without rewriting historical evidence. These checks use
Unicorn 2.1.4 and the existing external-call models; they do not prove GPU output
or equivalence for arbitrary inputs.

## player_update controls

The current 78.299401%, 88.239521% with labels masked, and 861/0/0 references
remain unchanged. A shared sixteen-byte vector/color object does recover the
native-sized slot at frame-bottom `0x38`, but it moves the neighboring vectors
to the wrong slots. The plain union and inherited-vector variants produce the
same 72.431138% result. Moving later spawn positions into the shared object
also merges distinct native call blocks. Rotating Fire Cough vector roles and
scoping its temporary reaches only 76.646127%, 85.344932% with labels masked.

[player-frames.json](player-frames.json) records the preserving frame observations
and their object hashes. The frame observer checks whole-COFF equality except
timestamp; unlike the full C2 trace harness above, it does not run a
missing-stream negative control. These rejected forms do not disprove the
shared-object hypothesis. The pending `turn_angle` form still improves the
label-masked score while worsening the scorer's duplicate-block pairing.
No player source was retained and no player runtime-equivalence claim is made.
The timeline source was not changed.

## Reproduce

Use new output directories; all builds use the pinned stock compiler. The
control verifier reconstructs every source from the pinned Git revision.

```sh
uv run --no-sync python tools/match/evidence/remaining-storage-controls-2026-09-26/verify_controls.py --out /tmp/storage-controls --jobs 3
uv run --no-sync python tools/match/evidence/remaining-storage-controls-2026-09-26/verify_region.py --scratch tools/match/scratches/projectile_render --out /tmp/storage-region.json
```

For each `historic`, `positions`, and `ion` suite:

```sh
uv run --no-sync python tools/match/evidence/remaining-storage-controls-2026-09-26/verify_execution.py --source tools/match/scratches/projectile_render/scratch.cpp --suite historic --out /tmp/storage-historic
```

For each `conventional` and `laser` suite, use the unchanged historical verifier:

```sh
uv run --no-sync python tools/match/evidence/renderer-house-style-2026-09-13/replay.py --source tools/match/scratches/projectile_render/scratch.cpp --suite conventional --out /tmp/storage-conventional
```

The preserving compiler trace can be regenerated with:

```sh
uv run --no-sync python scripts/c2/store_trace.py tools/match/scratches/projectile_render --out /tmp/storage-tint-trace --symbol '#3469' --symbol '#274' --symbol '#275' --detail
```

Symbol IDs belong to this pinned source/toolchain. The macOS sandbox in this
session made Unicorn's memory mapping trap; execution receipts were obtained
outside that sandbox, without changing the emulator or fixture contracts.
