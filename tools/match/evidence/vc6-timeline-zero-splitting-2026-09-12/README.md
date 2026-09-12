# Timeline zero splitting and remaining source constraints

**Zero sharing and the dead pointer store can coexist in stock compiler output.**
A counter-lifetime witness preserves the exact EDI pointer/zero store triplet
and uses EBX for the initial tests, outer count test, and final clears. It still
has the eight-byte copied owner, different register assignments, and different
scheduling. It is a mechanism witness, not a better candidate or recovered source.

The canonical scratch remains 113/115 instructions, 91.228070%, prefix 51,
13 clean aligned references, and a non-exact body. Source and flags are unchanged.

## The zero disappears through successive splits

[zero_allocation.py](zero_allocation.py) adds preserving entry/return hooks to
the allocation driver. Both observed whole COFFs equal their stock replays,
excluding only timestamp bytes 4–7. There are 107 canonical and 115 witness
events from the initial zero selection onward. Complete operand chains and
temporary descriptor words are retained in the generated raw traces.

The summary follows currently defined zero pseudo-instructions, rather than
assuming that an arena address continues to identify the same temporary.
Addresses are recycled after splitting. Counts below are instruction users,
not the number of zero definitions placed in different blocks.

| Stage | Canonical | Pointer-copy witness |
|---|---|---|
| Before allocation | One zero, 12 users | One zero, 12 users |
| First rewrite/split | Replacement zero, 9 users | Replacement zero, 9 users |
| Later split | Nine users remain together | Groups of six and three users |
| Final split | Groups of one and eight users | Groups of one, four, and two users; the final count clear has left these groups |
| Allocation outcome | Eight-use zero receives EBX | Remaining zero groups are replaced with constants |

The decisive group changes occur across `C2+0x204d6`; the rebuilt descriptors
are observed across `0x24b25` and `0x2158f`. The four-use witness group covers
the initial index initialization and scan comparisons. Its recorded cost at
descriptor `+0x3c` is -1. The canonical eight-use group's cost is +1.

Both pointer temporaries in the witness are separately presented to
`0x32f7c`, then both receive the same register descriptor, `C2+0xac9d0` (EDI).
The canonical final zero receives `C2+0xac880` (EBX). This is an observed
allocation difference; it does not prove that the extra pointer temporary
causes the zero split. An attempted early manual coalescing probe crashed its
modified replay and was discarded as invalid evidence.

[trace-results.json](trace-results.json) includes changing zero groups, their
actual instruction users, costs, priorities, allocation events, and replay
hashes. The observer does not change installed compiler files or game databases.

## Separate priority from retention cost

The queue insertion routine `0x31d21` orders temporaries using descriptor
`+0x0c`, with `+0x40` as a tie breaker. Canonical zero priorities initially
read -64 and -53; the corresponding witness priorities read -68 and -57.

[priority_controls.py](priority_controls.py) hooks all three callsites of that
queue routine and records every selected zero before and after intervention.
Changing either or both witness priorities to the canonical values produces
the same whole COFF as the witness control. Giving every zero a very low
priority also leaves its output unchanged. Priority equality alone therefore
does not explain this residual.

A different, narrowly selected intervention changes the four-use zero's
retention cost from -1 to +1. Together with the previously verified four-byte
extent reduction, it produces:

- 115 instructions, 90.434783% agreement, normalized prefix 48;
- 12 clean aligned references, zero reference problems, non-exact body;
- the native initial scan, exact pointer-store triplet, and native EDI loads;
- remaining differences in the outer zero test and final clears, with resulting
  branch offsets.

This requires one cost-field write and one extent-field write. It earns no
source or exact-match credit. [scan-cost-native-diff.txt](scan-cost-native-diff.txt)
contains the complete residual. Altering the other zero groups' costs produces
extra materializations or different registers; no tested intervention is exact.
All 25 modes, including controls, are in
[priority-results.json](priority-results.json).

## Stock-source lifetime witness

[zero-lifetime-witness.cpp](zero-lifetime-witness.cpp) moves `spawn_index`'s
initialization immediately before the outer loop, and resets it at the end of
each iteration. The count and active-flag clears use that reset value. The
resulting [assembly](zero-lifetime-witness.asm) retains:

```text
lea edi, dword [esi+0xc]
mov dword [esp+0x10], edi
mov dword [esp+0x10], ebx
```

It also retains shared EBX zero tests and EBX/BL clears. The initial count is
in ECX rather than native EDI, however, and other register choices and load
ordering differ. Its frame is still 32 bytes. Metrics are 115 instructions,
64.347826%, prefix 1, eight clean aligned references, zero reference problems,
and a non-exact body. This disproves a necessary incompatibility between the
pointer triplet and shared-zero behavior; it does not establish the original
counter scope or improve the canonical match.

[source_controls.py](source_controls.py) reproduces 121 successful builds:
26 lifetime controls, 33 initialization/declaration/loop-order controls,
27 count-lifetime/type controls, 11 register/stall-local controls, and 24
four-byte return/copy/postfix controls. Unsigned and short count types are
explicitly diagnostic and are not proposed semantic replacements. Declaration
permutations and register hints do not repair the lifetime witness. Of the
four-byte return controls, 22 reproduce canonical instructions and two retain
EDI loads but lose the home. None is exact or improves canonical agreement.
[source-results.json](source-results.json) retains every source and COFF hash,
native metric, and gate check.

## Remaining work

1. **Four-byte storage owner.** The successful copy mechanism still charges
   eight bytes to an object with one unused stored member. A credible stock
   source must retain the dead write with the native 28-byte frame. The new
   four-byte return/copy controls do not achieve this.
2. **Zero lifetime and register selection.** The stock counter witness proves
   coexistence, and the cost control isolates the scan's zero decision. Recover
   the native outer-loop sharing and allocation order without the witness's
   register permutations. Do not repeat priority-only or declaration-order
   permutations as though they were untested.

The next useful trace is the counter-lifetime witness against the pointer-copy
witness: compare the split regions and register affinities, keeping complete
operands and source identities. An early coalescing experiment needs valid
compiler def/use and block metadata before its result can be interpreted.

## Reproduce

Run from the repository root with
`UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python` before each
script path. Use the replay roots described by the earlier
[decomposition evidence](../vc6-timeline-decomposition-2026-09-12/README.md#reproduce).
The `--observer` input is its generated, preserving layout observer.

```text
zero_allocation.py --canonical-root /private/tmp/timeline-causal-proof/baseline --witness-root /private/tmp/timeline-pointer-home-trace-proof/shape/body-copy-relative --out /private/tmp/timeline-zero-splitting-verified
priority_controls.py --root /private/tmp/timeline-pointer-home-trace-proof/shape/body-copy-relative --observer /private/tmp/timeline-decomposition-layout-verified/observer.c --out /private/tmp/timeline-zero-priority-verified
source_controls.py --out /private/tmp/timeline-zero-sources-verified
```

Script paths are relative to this directory. The original witness source and
compiler hashes are pinned. Queue records contain temporary address, definition
address, priority before/after, use-count field, cost before/after, and flags.
Raw replay addresses are local identities, not portable symbol names.
