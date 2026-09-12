# Timeline rematerialization and the missing home store

**No source match was recovered.** Canonical source and flags remain unchanged:
113/115 instructions, 91.228070%, prefix 51, 13 clean references, non-exact body.
The new evidence separates keeping the derived pointer from producing its
immediately overwritten memory home.

## Late removal mechanism

Local Binary Ninja analysis of the pinned C2 binary identifies this path:

```text
0x32216  allocation analysis
  0x526d3  processes candidate definitions
    0x5259c  collects source dependencies and eligibility
    0x527b2  checks uses, base changes, addressing legality, and cost
    0x1f578  rewrites uses and removes the definition
```

The call sites in `0x526d3` are `0x52700`, `0x5273a`, and `0x5277c`.
The new call/return hooks observe the first two and the cost helpers inside
`0x527b2`; the earlier complete-operand trace locates the actual LEA removal
inside the enclosing `0x32216` call.

For the canonical pointer preserved through the early pass:

- `0x5259c` returns a dependency set and eligibility output 1.
- The use-cost helper `0x52a2b` returns 0; the definition-cost helper
  `0x52a3d` returns 1. Their controlling global at C2 RVA `0xac0b4` is 1.
- Disassembly confirms that this nonzero flag bypasses their displacement-byte
  cost calculations. Therefore merely making substitution larger is not a
  useful explanation under this profile.
- `0x527b2` returns 1 and the pointer is substituted away.

The earlier retaining control, `advance-after-pointer-template-relative`,
still reaches the first predicate as COPY and returns 0. Its watched pointer
never reaches the late collector or predicate in this replay. It is not a
positive example of the late predicate rejecting an otherwise comparable LEA.

## Two-stage intervention

`rematerialization.py` changes only selected returns for the watched compiler
temporary. These are diagnostic experiments; none of their output is installed
as a source candidate, checkpoint, or native provider.

| Intervention | Instructions | Agreement | Prefix | Clean refs | Pointer home |
|---|---:|---:|---:|---:|---|
| None | 113 | 91.228070% | 51 | 13 | Absent |
| Early only | 113 | 84.210526% | 14 | 12 | Absent |
| Late only | 113 | 91.228070% | 51 | 13 | Absent |
| Early and late | 114 | 85.589520% | 14 | 12 | Absent |

Late-only changes zero returns because the pointer has already disappeared.
Early-and-late changes exactly two returns and keeps `lea edi, [esi+0xc]`
with `mov edx, [edi]`. Heading remains entry-relative in this source. The
native `mov [esp+0x10], edi` does not appear. Initial zero-register sharing
and count-test code also differ.

The early intervention has two independently exercised forms: reject LEA
eligibility at `0x309bb`, or report a base-definition conflict at `0x31a50`.
Both give the same normalized outputs for the four modes above. This prevents
overinterpreting artifacts specific to one early rejection branch.

This establishes that simply preserving the canonical pointer does not cause
the allocator to emit the native home. It does not establish how the unknown
original source produced that store or that a source-level solution is absent.

## Actual cursor motion and a scalar dead home

The previous control labeled `ptr-bump-restore` contains `template_id += 0`.
Its generator comment overstated what it tested. The comment is corrected;
the historical plan, variant labels, and source bytes are unchanged.

`cursor_probes.py` supplies twelve sequenced cursor-motion controls, including
predecrement/postincrement, rewind versus reset, and inline byte-stream readers.
`refcursor_probes.py` adds eight pointer/reference counterparts. No expression
modifies the cursor twice through unsequenced call arguments.

`heading-predec-after-pos` is a useful partial observation:

```cpp
float heading = *(float *)--template_id;
int id = *++template_id;
creature_spawn_template(id, (const vec2f_t *)&pos, heading);
```

It emits 118 instructions, 66.094421%, prefix 1, 12 clean references, retains
the EDI template pointer, and contains `mov [esp+0x14], eax` for heading.
The bounded spawn-loop frame-access audit finds only that write to the slot:
no read or address-taking instruction, with ESP adjustments tracked across the
call. The passed position occupies a different stack range. This is a scalar
heading home, not the native pointer-valued adjacent overwrite.

`heading_trace.py` verifies the store's different IR history. Heading already
has a kind-2 memory destination at the first snapshot. After argument lowering,
its load/store pair is `0x60`/`0x63`. The pair survives through the early pointer
pass. Before `0x336f4`, both node identities are reused for integer COPY nodes,
with their roles swapped: the old store identity becomes the load and the old
load identity becomes the memory store. The verifier checks those identities
explicitly rather than inferring continuity from source lines. The destination
symbol also changes, so no unchanged memory-owner identity is claimed.

The canonical pointer instead reaches these passes as temporary definitions.
This scalar example is a useful memory-store lowering witness, but does not
explain a pointer home. The pointer/reference counterparts do not transfer
the float-value result into such a store.

## Other bounded controls

Six source/context controls reproduce the baseline normalized instructions:
`register` and const-pointer spellings, plus compiling the recovered
`creature_spawn_template` and `tutorial_timeline_update` before and after this
function in the same translation unit. This bounds those specific context
choices; it does not rule out all translation-unit effects.

Debug/profile controls test `/Zd`, `/Z7`, `/Zi`, `/ZI`, `/GX`, and `/Gi` with
entry-relative and pointer-relative heading. Ten builds reproduce baseline
instructions; both `/ZI` builds report D2016 because `/O2` and `/ZI` conflict.
Debug information and these exception/incremental controls do not explain the
home on this source.

## Reproduction and verification

The prior capture driver and complete-operand observer are reused. The ordinary
and observed control COFFs agree except for timestamp bytes 4–7, including the
retaining control. Late-only also remains whole-COFF identical. The intervened
objects intentionally differ; equality with stock is never claimed for them.
Source and C2 hashes are pinned. The float trace additionally repeats the
normal/capture/replay/observer and missing-stream checks.

First create the baseline replay using the adjacent earlier evidence:

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-timeline-late-removal-2026-09-12/counterfactual.py \
  --out /private/tmp/timeline-causal-proof
```

Then run this directory's `rematerialization.py` with
`--replay-root /private/tmp/timeline-causal-proof/baseline --out /private/tmp/timeline-remat-proof`.
Repeat with `--strategy conflict` and a different output directory. For the
retaining source, generate replays with the earlier consumer `trace.py` and
pass its `advance-after-pointer-template-relative` directory plus
`--retaining-control`.

Run each of `context_probes.py`, `debug_probes.py`, `cursor_probes.py`, and
`refcursor_probes.py` with `--out` pointing to its own temporary directory.
Run `heading_trace.py` with `--source` pointing to the cursor generator's
`heading-predec-after-pos/scratch.cpp`, `--capture-dll` pointing to
`/private/tmp/timeline-causal-proof/helper/capture.dll`, and its own `--out`.
Use `UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python` for
these commands too.

Adjacent JSON files retain full results. In rematerialization rows, hook indices
4/5/6/7 mean late predicate/use cost/definition cost/dependency collector;
word 9 is the original return and word 11 marks an intervention. Word 8 holds
the cost-mode global for indices 5/6 and the collector output for index 7.
Runtime addresses are compared only within their own replay.

The remaining discriminating evidence is still a source-produced pointer-valued
memory write with a known lowering history. No finite sweep here establishes
source exhaustion. Historical-installer comparison was also attempted locally,
but innoextract rejected the available installers; no historical-code conclusion
is drawn from that attempt.
