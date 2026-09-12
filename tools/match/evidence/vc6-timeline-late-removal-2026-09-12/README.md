# A second timeline pointer-removal route

The canonical source remains **113/115 instructions, 91.228070%, prefix 51,
13 clean references, and a non-exact body**. No candidate source or compiler
configuration change is retained. The experiment changes one decision in an
isolated loaded compiler replay. Its output is **not a source match**.

## New causal evidence

Rejecting the template pointer's eligibility at `C2+0x309bb` prevents its
removal in `0x306c1`, but does not keep it in final code. A later routine,
**`C2+0x32216`**, removes the surviving LEA and rebases the template-ID load to
the same entry base used by heading. This is a second removal route exercised
by the perturbed canonical input, not a claim about the original source's
compiler history.

The intervention uses the existing observer's watched compiler-temporary
identity. After the original predicate returns, it changes saved EAX from 1
to 0 only for that temporary. Exactly one return changes in the baseline
replay. No pointer, stack store, or desired instruction sequence is inserted.
Installed compiler files are unchanged.

| Boundary in the intervened replay | Nodes | Template pointer |
|---|---:|---|
| Before `0x306c1` | 170 | LEA and COPY |
| After `0x306c1` | 166 | LEA survives |
| Before and after `0x33569` | 159 | Same LEA survives |
| Before first `0x32216` call | 159 | Same LEA survives |
| After that call, before `0x32f7c` | 158 | LEA absent; ID load rebased |
| Before `0x336f4` | 153 | Pointer absent |

The `0x32216` call is at RVA `0x2fe4d`. Between its return and the hook before
`0x32f7c` at `0x2fe5f`, the caller only moves registers and pushes an argument.
The verifier checks disappearance of the actual node identity from the full
list, not just its source-line label. Both field-load identities survive;
the ID load changes from its distinct pointer base to the heading load's base.

The diagnostic body has 113 instructions, **84.210526%**, prefix 14, 12 clean
aligned references, and no dead pointer home. Earlier zero-register sharing
and count-test code also change. This does not demonstrate that the native
body is the baseline plus a disabled optimization.

The pointer-relative-heading source is a no-intervention control: its named
COPY has already been forwarded before the watched boundary. The selector
changes zero returns there and its whole COFF remains stock-identical. It
does not test suppression of that source's auxiliary pointer.

## Next useful question

Keeping the pointer through `0x306c1` alone is insufficient for this candidate.
What distinguishes a pointer that `0x32216` keeps from one it substitutes into
its consumers? Compare its operands, definitions, and uses with the already
measured pointer-retaining source control. The dead pointer-valued memory
write and reuse of its frame slot still need their own explanation.

This narrows the investigation beyond another sweep of pointer declarations.
It establishes neither source exhaustion nor a compiler ceiling.

## Broader native screen

`native_scan.py` checks every possible unprefixed `89`/`C7` MOV start across
the original executable sections: 448,888 bytes in the EXE and 306,153 in the
DLL, including bytes outside the curated function inventory. It screens
adjacent dword MOV destinations with the same ESP/EBP base and displacement
and no index register. All four hits coincide with known instruction
boundaries: three previously studied dxdiag zeroing overwrites and the
timeline pointer overwrite. The DLL has no hits.

This strengthens the previous 31-listing screen, but remains a bounded
instruction-pattern search. It excludes nonadjacent stores, prefixed starts,
and other addressing forms. Boundary attribution uses 1,283 EXE and 1,154 DLL
functions. Hits require manual review for control flow and deadness.

## Verification and reproduction

`counterfactual.py` first verifies normal, captured, replayed, and preserving
observed whole COFF equality, excluding only timestamp bytes 4–7. The existing
verifier also checks frontend-stream integrity and missing-stream rejection.
Unmodified decision observers remain stock-identical. `late_trace.py` verifies
that its additional hooks preserve both parent objects: stock for the control,
deliberately modified for the intervention. Source and C2 hashes are pinned
using the existing trace constants; flags are `msvc6.5 /O2 /GB /W3 /GR-`.

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-timeline-late-removal-2026-09-12/counterfactual.py \
  --out /private/tmp/timeline-causal-proof
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-timeline-late-removal-2026-09-12/late_trace.py \
  --out /private/tmp/timeline-causal-proof
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-timeline-late-removal-2026-09-12/native_scan.py \
  --out /private/tmp/timeline-native-scan.json
```

Adjacent JSON files retain results. Runtime addresses are compared only within
one replay. The output directory additionally holds generated observer sources,
complete-operand traces, frontend streams, objects, and disassemblies. No
intervened output is installed as a candidate, checkpoint, or native provider.
