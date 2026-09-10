# VC6 redundant stack stores: research and positive control

Research date: 2026-09-11. No exact published explanation was found for the
`quest_spawn_timeline_update` sequence:

```asm
004342f4  lea edi, [esi+0xc]
004342f7  mov [esp+0x10], edi
004342fb  mov [esp+0x10], ebx
```

The pointer stays useful in `edi`; its stack copy is immediately overwritten
with zero. The current candidate removes both the `lea` and the first store,
and accesses fields through `esi` instead.

## Published leads

Martin Heller's March 1999 Microsoft article, archived at CMU, documents VC6
copy propagation, dead-store elimination, and stack packing. Stack packing
allows locals with disjoint scopes to share storage. This makes stack-slot
reuse a relevant hypothesis, but the article does not establish the pass order
or explain this sequence.
[Developing Optimized Code with Microsoft Visual C++ 6.0](https://www.cs.cmu.edu/~rbd/doc/optcode.htm).

Microsoft's 2017 optimizer report describes avoidable stack traffic from
reference parameters and rerunning optimization after loop transformations to
catch newly exposed opportunities. This supports investigating interactions
between passes; it is evidence about a later compiler, not proof of VC6's
specific mechanism.
[MSVC code optimizer improvements](https://devblogs.microsoft.com/cppblog/msvc-code-optimizer-improvements-in-visual-studio-2017-versions-15-5-and-15-3/).

## Positive control in the same executable

Scanning the manifest's function ranges for adjacent `mov` stores to the same
ESP/EBP-relative address, with a register source in the first store, found the
timeline pair and three pairs in `dx_get_version_from_dxdiag`. No direct branch
within either function targets the second instruction of these pairs. This is
a narrow pattern scan, not exhaustive dead-store analysis.

The [dxdiag reconstruction](../../scratches/dx_get_version_from_dxdiag/scratch.cpp)
uses `ZeroMemory(&params, sizeof(params))` followed by four field assignments.
Stock `msvc6.5`, `/O2 /GB /W3 /GR-`, reproduces its entire 190-instruction body
exactly with 12 clean references. For example:

```asm
0041cdf8  xor ecx, ecx
0041cdfa  mov eax, [esp+0x10]
0041cdfe  mov [esp+0x34], ecx
0041ce02  mov [esp+0x34], 0x10
0041ce0a  mov [esp+0x38], ecx
0041ce0e  mov [esp+0x38], 0x6f
```

The following source controls are reproducible with [probe.py](probe.py);
measurements are in [results.json](results.json).

| Control | Match | Instructions | Body exact |
| --- | ---: | ---: | --- |
| Original `ZeroMemory` and assignments | 100% | 190 | yes |
| Explicit `memset` and assignments | 100% | 190 | yes |
| Aggregate `{0}` and assignments | 86.543536% | 189 | no |
| Field assignments only | 80% | 185 | no |
| Original source, append `/Oi-` | 85.039370% | 191 | no |

All five controls have 12 clean references. Disassembly inspection shows that
removing zeroing removes the redundant initialization stores; `/Oi-` emits a
`memset` call instead of inline stores. Aggregate initialization retains some
redundant stores with a different schedule.

From the repository root:

```sh
uv run --no-sync python tools/match/evidence/vc6-redundant-stores-2026-09-11/probe.py --out /tmp/vc6-redundant-stores.json
```

## Implication and limit

Ordinary source and the stock compiler demonstrably produce immediately
overwritten stack stores. Here the source trigger is intrinsic zeroing followed
by field assignment. This is a positive control for tracing when such stores
appear and survive optimization. The timeline's derived-pointer store is
different: neither a shared cause nor its original source has been established.
The next focused comparison is intrinsic/block-copy lowering and stack-home
assignment versus the already traced template-pointer removal. The timeline
candidate remains non-exact; these findings do not establish any matching limit.
