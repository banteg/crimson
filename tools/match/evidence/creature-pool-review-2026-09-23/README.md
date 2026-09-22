# Independent review of the creature pool-base recovery

Keep `b8e458085`. The source and reference waiver are supported by a fresh
review. The function remains non-exact. This review changes explanatory notes
and adds diagnostic evidence; it does not change the canonical source,
compiler settings, reference aliases, or matcher rules.

## Rechecked evidence

- The committed verifier rebuilt both sources and reproduced 3,480/3,480
  native execution observations, including ordered game-memory writes. The
  observation-file hash remains
  `2a637c890370ea92187fb0a2fc08d4750d1b02375b66f7ec7dda9a8a077b8d81`.
- The separate 12 cases from `creature-corpse-vectors-2026-09-13` also agree
  under the interaction verifier's target-changing callback model, with its
  disabled-model preservation checks. The pool-base verifier does not itself
  run these additional cases.
- Rebuilt metrics remain 58.547655% -> 66.666667%, 1,306 -> 1,311 candidate
  instructions against 1,338 native instructions, and references
  `226/0/1` -> `363/0/5`. Both normalized and encoded exactness remain false.
- All five reference mismatches were inspected with surrounding instructions.
  They pair different operations in the hold-target copy, projectile argument
  preparation, or contact block. The corresponding Y store, heading argument,
  shield load, perk call, and Veins of Poison load exist in the candidate.
  The X/Y stores themselves retain their semantic order; register assignment
  makes the aligner pair target's Y store with candidate's X store. The longer
  contact-block misalignments are not literally adjacent instruction swaps.
- `match validate`, `native verify --require-game-closure
  --allow-absent-toolchain`, and 73 tests under `tests/native` passed.
  `match regressions --base 73983477c --waivers
  tools/match/regression-waivers.json` reports one changed function and zero
  unwaived errors. Its sole waiver is bound to this commit's actual parent.

These remain finite observations under explicit callback models, not a proof
of whole-game equivalence. Native artifact verification reports function and
game-owned closure; it does not report closure of all external references.

## Correct native pointer identities

The earlier residual summary mislabeled two homes. These are ESP offsets at
the indicated instructions, after the prologue's callee-save pushes:

| Value | Native definition | Storage |
|---|---|---|
| `&health` | `0x004262b0` | `esp+0x24` at `0x004262b7` |
| `&lifecycle_stage` | `0x00426569` | `esp+0x28` at `0x00426575` |
| `&collision_flag` | `0x00426586` | `esp+0x30` at `0x0042658f` |
| `&size` | `0x00426e2f` | `esp+0x14` at `0x00426e36` |
| `&attack_cooldown` | `0x00426f42` | EBP |
| `&target_player` | `0x00426f6f` | EBX |

Native loads health and compares it **before** forming/storing its pointer:
`fld; fcomp; lea edi; mov [esp+0x24],edi; fnstsw`. The older
pointer-rematerialization README's claim that native stores the pointer
before that load was incorrect and has been corrected.

## Retention controls on the current source

`verify.py` reuses the established callsite observer and predicate controls,
with source-bound symbol selection for health, lifecycle, collision, size,
and cooldown. The ordinary capture/replay/observer control preserves the
whole COFF except its timestamp and rejects a missing frontend stream. A
second disabled observer selecting four values also preserves the whole COFF.

| Diagnostic | Frame | Instructions | Alignment | References ok/problems |
|---|---:|---:|---:|---:|
| Stock / disabled observer | `0x6c` | 1,311 | 66.67% | 363/5 |
| Retain health only through `0x306c1` | `0x6c` | 1,311 | 66.67% | 363/5 |
| Retain health through reconstruction and splitting | `0x70` | 1,317 | 69.00% | 363/6 |
| Retain the four home values through both mechanisms | `0x80` | 1,333 | 65.82% | 345/8 |
| Also retain cooldown | `0x80` | 1,362 | 68.30% | 370/6 |
| Native | `0x7c` | 1,338 | 100% | — |

Early-only retention is byte-neutral: health survives `0x306c1`, then
disappears inside the first `0x32216` allocation analysis. The full health
control recovers native's opening scaled health LEA and its `esp+0x24` home,
including the load/compare/LEA/store order. Retaining the four home values
does not simply fill the 16-byte frame deficit: allocation adds 20 bytes.
These coupled lifetime/allocation effects refute an additive frame argument.

No compiler-mutated object is a source candidate, and no runtime-equivalence
claim is made for those objects. The canonical source remains unchanged.

## What the `0x4ca2e` lead actually means

Read-only inspection of the pinned C2 binary establishes:

- `0x4ca2e` is inside the previously identified regional-splitting routine
  `0x4c47a`, reached from `0x8e506`, `0x333c0`, `0x33512`, and `0x3353c`.
- That path clones a definition for selected use sites (`0x4c9c3` calls
  `0x1ef1`; `0x4c9f9` calls `0x2c0b`). Only after processing that list does
  it set descriptor byte `+5`, **mask `0x10`** at `0x4ca2e`.
- The later reconstruction predicate `0x527b2` walks the proposed
  definition's **source operands**. At `0x5280a` it tests mask `0x10` on a
  source temporary; a set bit takes `0x8ee8e` and returns false.
- This differs from descriptor mask **`0x04`**, which excludes the early
  substitution at `0x306c1`. That earlier pass clears its exclusion bit.

Thus `0x10` is evidence of an already performed regional transformation,
not an identified source qualifier for keeping a field pointer. In particular,
setting it on a pointer is not the same as making that pointer's own
reconstruction predicate reject: the predicate tests its dependencies.

The next source hypothesis should concern the definition/use graph of the
shared index/base and field pointers across regions, including inlined helper
boundaries that change that graph. Merely moving declarations or wrapping
unchanged code in a helper need not change any compiler decision. First trace
which source operand or dependency prevents early substitution and later
reconstruction in a small natural source control; then require all four homes,
the target-byte pointer in EBX, and the native frame together. This is a
testable direction, not a recovered source spelling or proof of exhaustion.

## Reproduce the new compiler controls

```sh
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/creature-pool-review-2026-09-23/verify.py \
  --out /tmp/<fresh-directory>
```

The output contains observer sources, objects, full selected IR snapshots,
decision records, candidate assembly, and `results.json`. The optional
`--preserving` argument accepts a verified trace only if its source and hook
profile match. The adjacent receipt is from a successful replay; exact raw
arena addresses and observer hashes are process/path dependent.
