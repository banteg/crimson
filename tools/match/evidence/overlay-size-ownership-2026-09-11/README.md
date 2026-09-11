# Overlay sprite-size ownership

The alive-player shadow and small muzzle flash now own separate scalar sizes.
The prior source reused `sprite_size` for those values as well as the dead
shadow, torso shadow, and normal flash. Separating the two observed lifetimes
recovers native stack placement without changing arithmetic or call arguments.

Normalized alignment rises from **93.031359% to 94.773519%**, gaining
**79.825784 fuzzy-weighted bytes** and reducing the remaining gap to
**239.477352 bytes**. Instructions remain **1,148/1,148**, prefix remains nine,
and all **331 references** remain clean. Whole-function normalized and encoded
exactness remain false; this grants no additional whole-function match.

The preceding source, from commit `a8be8e9247ae996c18cd691321fc0d9dda3c6538`, is
preserved in `before.cpp`, SHA-256
`6b8b8274afee4c30765b527b19b87ef019423e218bf151d6a292662f13800986`.
The recovered source SHA-256 is
`893863b7f9421b1aef6bd0e72818a4f024c49d4190543f0534e5fa84427dd484`.

## Native stack evidence

`verify.py` checks the relocated before/current instruction streams directly:
every changed instruction differs only in an ESP displacement. Operations,
instruction sizes, addresses, other operands, and resolved references are
unchanged between these two candidates. This is instruction recovery; the
proof finds no runtime behavior defect in the preceding source.

The native runner records the actual entry-relative ESP at each executed
instruction. The verifier joins these observations to unambiguous paired stack
accesses and compiler source listings. Thus it accounts for pushes between
accesses rather than treating raw `[esp+offset]` differences as different
local homes. All 199 checked native/candidate stack-access pairs are exercised.
Three EBP-based virtual calls are explicitly excluded from frame-local claims,
and one ambiguous stack-instruction pairing remains recorded and excluded.
Candidate names describe candidate source; they do not identify original
source variables or prove native lexical lifetimes.

| Candidate value | Observed native entry slot | Before | Recovered |
| --- | --- | --- | --- |
| Shared sprite size | -36 | -40 | -36 |
| Shield half-size | -40 | -36 | -40 |
| Alive-shadow size | -24 | shared -40 | -24 |
| Small-flash size | -24 | shared -40 | -24 |

Across all paired accesses, **26 stack accesses are restored and six are
displaced**, reducing mismatches from **48 to 28**. The six regressions concern
an unnamed temporary used for body-quad size arguments at native
`0x4287d7`, `0x4287e1`, `0x428c05`, `0x428c0f`, `0x428d6a`, and `0x428d74`:
their native slot is -36, while the new candidate uses -40. Every changed pair
and every remaining mismatch is retained in `results.json`. No pairing rule,
alias, waiver, or exactness criterion is relaxed.

## Stock compiler observation

`verify_stack.py` adapts the existing HUD observer to this zero-parameter
function. It reads the ordered symbols and directed interference sets before
C2 stack coloring, then reads the final descriptors. The scoped allocator
model predicts all **41 baseline** and **43 recovered** descriptor offsets.
There are 43 and 45 symbols respectively, with seven allocation groups and
the same 44-byte local frame in both builds.

The shared sprite-size use count falls from ten to six. The half-size retains
eight uses and now precedes it in allocation order. The two new size locals
each have two uses and share the -24 group. This explains the measured
candidate allocation change; it does not establish unique original source.

The observer retains the existing C2 call-site guards at RVAs `33cde` and
`5840f`, saving/restoring integer registers and flags around reads. It does
not modify compiler data or on-disk compiler binaries. Normal, captured,
replayed, and observed whole COFF objects agree except for the timestamp.
Withheld-stream, truncated-trace, and corrupted-offset controls are rejected.
`stack-before.json` and `stack-current.json` retain the graphs, allocation
orders, descriptors, capture checks, source identities, and backend hash.
The observed backend SHA-256 is
`d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a`.

## Machine fixtures and source controls

All **851 native/before/current cases** agree in complete ordered call argument
bits, permitted global writes, stored trail-distance bits, and unchanged player
and creature storage. The inputs comprise the prior 239 tint/trail/body cases,
12 explicit aura/dead/alive/shield/weapon-flag controls, and 600 deterministic
varied normal/small muzzle flashes. The latter vary camera and player positions,
size, alpha, time, headings, flash strength, and shield strength with seed
`2026091112`. The 239 prior call hashes are retained and reproduced.

The read-only stack observer reproduces the ordinary runner's entire returned
trace in all **753 observation controls**. All **2,553 instrumented executions**
check restored x87 control word `0x037f` and an empty x87 stack, in addition to
the parent's stack, saved-register, control-transfer, and write guards.
The native executable is pinned to SHA-256
`771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4`.

`source-controls.json` preserves 56 hash-checked, compiling controls: nine
quarter-size forms, eleven copy/accessor forms, all fifteen nonempty subsets
of four scalar-size splits, seven normal-flash forms after the retained split,
and fourteen explicit body-size argument forms. `verify_controls.py` rebuilds
each exact source and checks its instruction count, score, and reference
results. A named quarter-size vector reaches 94.993470% after the split but
adds an instruction beyond the native count; it is not retained. No tested
body-size argument owner recovers the six displaced temporary accesses while
improving the retained metrics. These controls bound their source forms, not
the function's matchability, and do not claim semantic equivalence for every
compiled variant.

The preceding tint/trail verifier also passes against the recovered source:
239 fixtures agree, all 18 distance controls remain rejected, and the local
40-byte tint window remains present. All 512 matching/native tests pass.

Grim calls remain recording thiscall stubs, effect texture selection is a
recorded no-op, and perk queries use fixture values. `D3DXVec2Normalize` is a
shared float32 sqrt/divide model, not execution of the external DLL. This is
bounded PC64 caller and stack evidence, not PC24, graphics-backend, pixel,
all-input, or whole-function equivalence. Python and Zig are unchanged.

## Reproduce

From the repository root:

```sh
uv run --with unicorn==2.1.4 --with capstone python tools/match/evidence/overlay-size-ownership-2026-09-11/verify.py --out /tmp/crimson-overlay-size-proof
uv run python tools/match/evidence/overlay-size-ownership-2026-09-11/verify_controls.py --out /tmp/crimson-overlay-size-controls
uv run python tools/match/evidence/overlay-size-ownership-2026-09-11/verify_stack.py --out /tmp/crimson-overlay-size-stack-after
uv run python tools/match/evidence/overlay-size-ownership-2026-09-11/verify_stack.py --source tools/match/evidence/overlay-size-ownership-2026-09-11/before.cpp --out /tmp/crimson-overlay-size-stack-before
uv run --with unicorn==2.1.4 --with capstone python tools/match/evidence/overlay-tint-trail-2026-09-11/verify.py --out /tmp/crimson-overlay-size-prior-proof
uv run pytest tests/test_match*.py tests/native --no-cov
```

Unicorn requires local JIT permission. The compiler observer requires the
repository's pinned VC6.5 toolchain and Wibo. Saved results identify the actual
source, compiler, object, runner, fixture, and observation inputs.
