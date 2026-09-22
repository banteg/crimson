# Creature health-pointer reconstruction and lifetime splitting

The missing native health-pointer home is controlled by more than retaining
its first LEA. Four reconstruction routes and regional splitting must be
separated. A diagnostic control now emits a stored health pointer, but with
an incorrect 128-byte frame and instruction order. No source match is claimed.

Canonical source is unchanged: 1,306/1,338 instructions, frame 124 bytes,
58.547655%, prefix 10, 226 aligned references with one problem, non-exact.
This follows the [offset-unit investigation](../creature-offset-units-2026-09-22/README.md).

## The removal routes

Local Binary Ninja inspection of pinned C2 and call/return observations identify:

| Route | Enclosing code | Decision being controlled |
|---|---|---|
| Early address substitution | `0x306c1` | Descriptor byte `+5`, mask `0x04` excludes substitution; that pass clears it |
| Allocation analysis | `0x32216 -> 0x526d3` | `0x527b2` called at `0x5273a` |
| Spill handling | `0x33230 -> 0x6a63e` | Same predicate called at `0x6a6b9` |
| Final allocation loop | `0x2fb58 -> 0x52624` | Same predicate called at `0x52659` |

All RVAs refer to C2 SHA-256
`d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a`.
The latter three paths reach `0x1f578`, which substitutes the computed address
into consumers and removes its definition. Returning zero from the selected
predicate prevents that route; it does not prevent another caller trying later.

The first allocation call's entry and return snapshots directly show the
health LEA disappearing unless its first late predicate is rejected. Later
controls progressively reject the spill and final-allocation attempts. Whole
COFF equality proves that blocking only the first one, two, or three routes
has no final effect on this candidate.

## The temporary identity changes

Keeping a fixed temporary descriptor is insufficient. After regional splitting,
the original LEA still has its original node identity and source line, but its
destination points to a different descriptor. A descriptor-only selector would
silently miss the final-allocation decision.

Tracking the original definition catches all three later reconstruction
attempts and retains one LEA in the output. Following the actual named health
symbol instead catches **seven** positive reconstruction decisions: two before
splitting, then five in final allocation. Four of those five definitions are
new nodes, at function-relative source lines 134, 479, 606, and 614. Their
health-symbol owner is unchanged; their descriptors differ from the initial
one. Identities are compared only within each replay.

The retained original definition alone does not give the native lifetime.
It can serve an early region while later regions reconstruct their own pointer.

## What produces a stored pointer

At `0x333ad`, the `0x33230` spill handler calls `0x21f97` for the watched LEA.
The predicate returns one, allowing `0x4c47a` to split/reconstruct its value
around regions of use. The full-value control permits this and subsequently
rejects all five final reconstruction attempts.

The home control instead rejects this predicate for the health value. The
compiler then emits a real pointer store:

```asm
fld dword [esi+health]
fcomp dword [zero]
lea edi, dword [esi+health]
mov dword [esp+0x20], edi
```

This is not the native sequence: native forms and stores the pointer before
its initial health load, uses scaled addressing, and reserves 124 bytes. This
control reserves **128** bytes. Its score falls substantially despite exposing
the missing storage mechanism.

| Control | Positive late decisions rejected | Instructions | Frame | Final result |
|---|---:|---:|---:|---|
| Stock observer | 0 | 1,306 | 124 | Stock whole COFF |
| Early substitution excluded | 0 | 1,306 | 124 | Stock whole COFF |
| Plus allocation reconstruction rejected | 1 | 1,306 | 124 | Stock whole COFF |
| Plus spill reconstruction rejected | 2 | 1,306 | 124 | Stock whole COFF |
| Original definition retained through all routes | 3 | 1,307 | 124 | One retained health LEA; no pointer home |
| Named value retained across cloned definitions | 7 | 1,311 | 124 | Regional pointer definitions; no pointer home |
| Named value kept without regional splitting | 3 | 1,315 | 128 | Stored pointer; wrong frame/order |

The last row's three decisions are allocation reconstruction, spill
reconstruction, and regional eligibility. It no longer reaches a positive
final reconstruction decision for this value. None of these compiler mutations
is installed in source, a provider, or the report's candidate set.

## Two source controls

Both credible declaration mechanisms emit exactly the canonical function bytes
and relocation descriptors:

- A field reference: `float &health = creature_pool[creature_index].health`,
  with its uses adjusted from pointer dereference to reference access.
- A pointer temporary bound to a reference:
  `float *const &health = &creature_pool[creature_index].health`.

They do not exercise the desired longer storage lifetime. No declaration-only
change is retained. These controls do not establish that all source shapes are
exhausted.

## Next constraint and verification boundary

A useful source hypothesis must explain why the health value remains live
across its separated regions, with an early stored pointer and the native
124-byte frame. Preserving a single LEA or matching one intermediate descriptor
is too weak. The independently measured offset-unit and animation-loop
constraints still apply.

The verifier performs normal/captured/replayed/observed whole COFF checks with
only timestamp excluded, pins compiler/source inputs, and rejects a withheld
frontend stream. Seven controlled replays retain complete operands at the
standard twelve boundaries and the first allocation call's entry/return.
Decision records include the definition node, source line, symbol owner,
current and initial temporary descriptors, original Boolean return, and whether
it changed. All later decision sites are still observed; only repeated full
function dumps are omitted. The two source controls compare encoded bytes and
complete relocation descriptors, not scores alone.

No runtime equivalence claim is made for compiler-mutated objects. The prior
3,480-fixture receipt applies to the unchanged canonical source and to the two
byte-and-relocation-identical source controls. The mutated objects are used
only to isolate compiler choices.

```sh
UV_CACHE_DIR=/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/creature-pointer-rematerialization-2026-09-22/verify.py \
  --out /tmp/creature-pointer-proof
```

Use a fresh directory. Raw compiler artifacts and full selected snapshots stay
there; adjacent `results.json` retains compact checked results and decisions.
