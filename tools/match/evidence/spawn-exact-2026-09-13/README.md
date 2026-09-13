# Exact creature spawn recovery

`creature_spawn_template` matches all **3,159 instructions, 14,099 encoded body
bytes and 363 positional references** at `0x430af0..0x434203`. Both native matcher
exactness gates pass. Both returns balance, every CFG node is covered, all four
retry-table destinations agree, and neither body has terminal padding.

Canonical source SHA-256:
`7e06761cd2ed01570971b49a51c4e6c892ac1267ced51cf926b0594616ef35aa`.
Extracted object-body SHA-256:
`afae78edc58fede721726293f804485be9fcf67db7794650d690adc8d819d4ae`.
The matcher resolves relocations before encoded comparison; the object-body hash
is not a claim that unresolved COFF relocations equal PE addresses.

## Recovery by residual

The starting source already contains the previous
[grid dispatch and port correction](../spawn-grid-dispatch-2026-09-11/README.md).
This continuation recovers source organization and compiler behavior:

- SDK vector construction, addition and scaling recover the native x87
  intermediate stores for grid and chain positions. Color values retain their
  construction and aggregate-copy boundaries.
- Separate formation velocity and tint lifetimes recover the native `0x48`
  frame and its reused homes. Readonly zero velocities need plain POD storage;
  they do not need the SDK arithmetic constructors.
- Native RNG publication separates integer remainder calculation from float
  conversion across alpha stores. The red spider also publishes green/blue
  between those operations. Disjoint RNG, angle and spawner locals share storage
  with every use following assignment.
- Grid child color follows reward and precedes maximum health. The corresponding
  ring boundaries and the chain `for` induction recover scheduling and register
  reuse. The ghost path retains both native type stores.
- A named grid-offset reference and a chain-position value local to its actual
  use recover the final two x87 add pairs. Commuting the operator implementation
  alone is byte-neutral. These are reproducing lifetime controls, not proof of
  the original author's variable names or exact source spelling.

No compiler flags, reference aliases, function boundaries, matching rules,
instruction bytes or padding were changed to obtain credit.

## The three delayed loads: an alias-analysis budget

The last three delayed EDI `1.0f` loads were not caused by their nearby scalar
stores. Read-only compiler observations locate the difference in the scheduler's
memory dependencies. An earlier control has distinct alias classes for the
seven blue-creature stores. After more SDK value temporaries are introduced,
all seven collapse to alias class 3, creating write-after-write edges that
serialize the stores and delay the constant load.

The pinned VC6 C2 field collector at `C2+0x1afd0` stops collecting when the count
reaches `0x400 - alias_base_count`; base allocation at `C2+0x5d456` also checks
`0x400`. The retained Binary Ninja excerpts are in `alias-analysis.json`.
The base counts are **448** for `grid-b2-add`, **538** for
`color-c4-ctor-assignment`, and **469** for the final source. The first and final
sources have seven distinct classes in each blue block; the constructor control
has one. Reusing disjoint scalar locals and using POD zero vectors restores the
field distinctions while preserving all required color copies.

`compiler.py` records the actual dependency graphs before and after critical-path
ranking, field alias classes and compiler counters. Its hooks preserve registers
and flags and validate their CALL destinations. Normal, captured, replayed and
observed **whole COFFs** must agree except timestamp; withholding the expression
stream must fail. The observed pointer-option globals remain zero for all three
sources. The hook process changes no compiler choice or emitted instruction.

The general tracer now supports 16,384 nodes and `--passes-only`. The final
source also passes that public command and its verified reader; the manifest is
retained in `pass-boundaries-receipt.json`. This function
has more than 4,096 IR nodes; recording every allocation occurrence produced
unnecessary trace volume. The narrower option retains the 12 pass boundaries
and the same preservation and failure controls. This tooling earns no match
credit by itself.

## Proof and controls

The source graph retains **254 compiling builds**, including the predecessor,
with source and extracted-body hashes. The final path contains 58 transformations
from the predecessor; the recovered and formatted final sources are both exact.
`recover.py` reconstructs each experiment and checks every patch preimage.
`verify.py` rebuilds all 254 and requires their recorded instruction counts,
reference results and exactness flags, preserving negative evidence alongside
the successful path.

`positions.py` checks all 3,159 instructions, 363 reference operands, 211 direct
branches, four retry-table edges and 712 stack accesses. Altered branches, reference owners, stack
locations and table destinations must be rejected. A real source mutation of
the grid stride must fail both exactness gates.

`replay.py` passes all **2,928 native cases**, including ordered writes, creature
and spawner state, globals, returns, calls and RNG. It covers PC24/PC64, all
spawn families, difficulty, retry, demo and pool overflow cases using the
previous package's original native caller and allocation helpers. Wrong stride
and omitted-row controls must change state, RNG draw count and writes.
Deterministic RNG and recorded callback boundaries remain modeled as documented
by that package. This finite execution coverage does not establish arbitrary
inputs or whole-game/rendered equivalence; full function identity comes from
the separate encoded-body proof.

## Reproduce

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/spawn-exact-2026-09-13/verify.py \
  --out /private/tmp/spawn-exact-proof

UV_CACHE_DIR=/private/tmp/crimson-uv-cache \
  uv run --offline --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/spawn-exact-2026-09-13/replay.py \
  --out /private/tmp/spawn-exact-replay

UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/spawn-exact-2026-09-13/compiler.py \
  --out /private/tmp/spawn-exact-compiler
```

Use `verify.py --final-only` for the final body and corruption controls without
rebuilding intermediate sources. `proof-receipt.json`, `native-receipt.json` and
`compiler-receipt.json` retain hash-bound results. Full per-case observations and
raw compiler traces are regenerated in the requested output directories.
