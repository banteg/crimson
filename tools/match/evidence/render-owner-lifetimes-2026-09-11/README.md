# Renderer index and living-body ownership controls

This pass tests the ion-chain index lifetime in `projectile_render` and the
four remaining living-body argument stack accesses in `player_render_overlays`.
**Neither canonical source changes.** No additional exact function, native-link
credit or runtime bug fix is claimed. The retained scores remain **60.268007%**
and **97.431432%**, respectively.

The useful result is a distinction between source forms that merely change
alignment and forms that recover a predicted native instruction property.
The latter still leave competing lifetimes to recover. These bounded controls
are not evidence that either function is exhausted or unmatchable.

## Ion-chain index lifetime

Native saves the first `creature_find_in_radius` result in EDI, computes
`9*i`, then `19*i`, then shifts ESI by three to retain `152*i`. Coordinate
reads use `[ESI + absolute-field-address]`. The canonical candidate saves the
index in ESI, retains `19*i` in EBX, and uses scaled `[EBX*8 + field-address]`
operands. Native and the canonical candidate keep the primary-projectile
position in EBP in the first coordinate subtraction.

A named byte offset shared by both source coordinate expressions recovers
EDI for the search result, `SHL ESI, 3`, and all four candidate direct field
operands as `[ESI + absolute-field-address]`. It also moves the primary
position from EBP to EBX, and reduces whole-function alignment. It does not
recover the complete native instruction span: native has **six** direct
coordinate reads between the two search calls, while these candidates have
**four**. The first multiply's temporary register and other scheduling also
remain different. [verify_instructions.py](verify_instructions.py) checks
these properties against native and retains the selected instructions in
[instructions.json](instructions.json).

| Source form | Alignment | Instructions | Clean / problematic references |
| --- | ---: | ---: | ---: |
| Canonical source | 60.268007% | 2,949 | 471 / 13 |
| Named creature pointer, captured after UV calls | 60.760342% | 2,950 | 467 / 13 |
| Named byte offset, captured after UV calls | 56.204991% | 2,950 | 445 / 11 |
| Named byte offset, captured before UV calls | 59.320047% | 2,950 | 465 / 13 |

Native has 3,021 instructions. The pointer form obtains a higher positional
score but materializes a creature pointer, replacing later absolute field
references with pointer-relative accesses. This is different from native's
retained byte offset. It is kept as a control rather than promoted on score.

The **37 controls, including baseline**, have **12 distinct encoded bodies**:

- Creature pointer/reference, position pointer/vector reference and integer,
  unsigned or float-stride offset owners, before or after the UV calls.
- Offset type, constness and declaration scopes; tail and primary-position
  ownership; reuse of inactive outer counters.
- Offset used at just one coordinate expression, or expanded inline at both.
  These last forms, unsigned search index and inactive-counter reuse compile
  to the canonical body byte for byte. A separately retained value consumed
  at both expressions is the discriminating control for the recovered shift.

[verify_ion.py](verify_ion.py) reconstructs the named pointer and byte-offset
forms and compares each with **384 historical native ion-chain fixtures**.
Both agree on the complete ordered calls and checked state. Native image,
function, original call hashes and saved projectile/player/creature states
are checked against the unchanged parent receipt.
[ion-validation.json](ion-validation.json) binds the results to both source
and body hashes. This uses the parent's PC=64 cases, native creature search,
and recording graphics/D3DX callbacks; it establishes no arbitrary-input,
PC=24 or pixel equivalence.

The next source hypothesis should account for the primary-position owner
remaining in EBP while the byte offset remains in ESI, and explain native's
two additional coordinate loads. Merely spelling the multiply differently
has already been distinguished from retaining its result at both uses.

## Living-body argument ownership

The four native-relative offsets remain **2165, 2175, 2522 and 2532**.
They use `[ESP+0x18]`; the canonical candidate uses `[ESP+0x14]` at the paired
accesses. The preceding [muzzle proof](../overlay-muzzle-ownership-2026-09-11/README.md)
establishes the dynamic stack pairing and the 202-access comparison.

The **34 controls, including baseline**, have **26 distinct encoded bodies**.
They capture either or both living-body sizes using the existing sprite-size,
alive-shadow-size or shadow-vector owner, a fresh scalar/vector, or references
and pointers. Nine controls capture before the geometry computation instead
of immediately before the draw. No tested control exceeds the canonical score.

Capturing both sizes early in a fresh `living_body_size` variable produces
the **same encoded function and the same complete COFF except its timestamp**.
The stock-C2 observer confirms the same 45 symbols, seven allocation groups
and 44-byte frame. The four-use unnamed symbol at allocation index 4 becomes
a named local, but remains in the -40 allocation group. Two conflicts disappear
without changing the groups or homes. The descriptor-check count increases
from 43 to 44 because the observer can now check that additional named local.
The reference trace is the preceding muzzle package's `stack-current.json`;
the new trace is [overlay-stack-early-owned.json](overlay-stack-early-owned.json).
The missing-stream, truncated-trace and changed-offset negative controls pass.

Reusing `sprite_size` at both early captures changes 16 normalized instructions.
It leaves the four living-body accesses at their existing slots while moving
other previously correct homes. Thus making the size explicit is insufficient
in these tested lifetimes. A useful next experiment must change the competing
scalar allocation order or conflicts without displacing the already recovered
dead-body and muzzle homes. The observer explains these candidate builds;
it does not identify unique original variable names or scopes.

## Reproduction

The two `*-before.cpp` files freeze the canonical inputs. The two
`*-controls.json` files contain line edits with checked old text, source and
body hashes, scores and reference counts. [verify_controls.py](verify_controls.py)
reconstructs and recompiles all **71 controls** with the ordinary matcher,
reference audit and unchanged compiler flags. Every recorded body and metric
is reproduced in [control-results.json](control-results.json).

```sh
uv run python tools/match/evidence/render-owner-lifetimes-2026-09-11/verify_controls.py \
  --out /tmp/crimson-render-owner-controls
uv run python tools/match/evidence/render-owner-lifetimes-2026-09-11/verify_instructions.py \
  --out /tmp/crimson-render-owner-instructions
uv run --with unicorn==2.1.4 python \
  tools/match/evidence/render-owner-lifetimes-2026-09-11/verify_ion.py \
  --out /tmp/crimson-render-owner-native
uv run python tools/match/evidence/overlay-size-ownership-2026-09-11/verify_stack.py \
  --source /tmp/crimson-render-owner-controls/player_render_overlays/early-living_body_size-01/scratch.cpp \
  --out /tmp/crimson-render-owner-stack
```

The stock VC6 toolchain and native-runner JIT permission are required locally.
No matcher rule, reference alias, waiver, compiler binary or gameplay source
is changed by this package.
