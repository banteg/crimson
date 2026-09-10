# Testing the GPT Pro timeline hypotheses

The tests explain a real distinction between pointer-retaining and
pointer-folding source controls, but produce **zero new matches**.
`quest_spawn_timeline_update` remains **113/115 instructions, 91.228070%
normalized agreement, prefix 51, 13 clean aligned references, and
`body_byte_exact: false`**. Its canonical source and compiler flags are unchanged.

The [GPT Pro consultation](https://chatgpt.com/c/6aa32f9b-0378-83ed-a4e2-7255e34c9a4a)
proposed separating three requirements: retaining the derived address for field
loads, retaining a pointer-valued memory write, and placing that write in the
stack range subsequently used by spread. These experiments test the proposed
consumer-rewrite boundary, pointer-copy mechanism, two source hypotheses, and
partial positives among the 98 previously recorded source controls.

## Consumer rebasing happens inside the identified pass

The previous observer recorded only the first operand on each side of an IR
node. The new observer follows each complete operand chain and records its
seven common words. It treats undocumented flags as raw data. This exposes the
actual base symbols of the heading and template-ID loads instead of inferring
consumer behavior from disappearing pointer-definition nodes.

For the canonical candidate, both load-node identities survive the observations
after argument lowering. Immediately before `C2+0x306c1`, heading still uses its
own derived-address symbol and the ID load still uses the template-pointer
symbol. Immediately after that routine, both use the entry symbol. The pointer
LEA/COPY definitions disappear in the same interval.

**The canonical result rejects the specific hypothesis that the final
entry-relative consumer rewrite happened earlier and `0x306c1` merely deleted
already-obsolete pointer definitions.** It does not identify the unavailable
original source's compiler history.

Equal output does not imply equal IR history. Changing heading to
`((float *)template_id)[-1]` produces the same final normalized instruction
stream, but `0x30308` first forwards the named pointer's COPY to an auxiliary
base. The subsequent `0x306c1` still performs the final entry-relative rebasing
of both loads. The verifier distinguishes these events by load-node and symbol
identities within each replay.

## A regressed source is a useful partial positive

`mine.py` rebuilds the exact 98 sources from the previously committed generator,
including regressed controls. It records all computed addresses and register
stores to the frame, and screens for same-basic-block frame overwrites with no
intervening direct read. The screen follows ESP changes across pushes and stack
cleanup, stops at branches/calls, and recognizes the native pointer/zero store
pair as a positive control. None of the 98 candidates has a pair under this
screen. This is a bounded structural screen, not general alias or path analysis.

Manual inspection finds an address-retention witness:
`advance-after-pointer-template-relative`. It saves the current template pointer
before advancing the entry cursor and uses that pointer for both spawn fields.
Its final code includes `mov eax, [esi-4]` and `mov edx, [esi]` before the spawn
call. The pointer remains live through the spawn loop. This is a **partial
mechanism witness**, not an accepted reconstruction: it has 162 instructions,
27.436823% agreement, prefix 1, five aligned references and one reference
problem. Its cursor-related frame stores are live; there is no immediately
overwritten pointer home.

A preserving trace of this control shows that `0x306c1` keeps the template COPY
and rewrites the heading load to the template base. Both loads then retain that
base through entry to forward allocation at `0x336f4`.

We also observe the actual eligibility predicate and its return value:

| Observation | Canonical candidate | Retaining partial control |
|---|---|---|
| Watched pointer definition reaching `0x309bb` | `LEA` (`0x12`) | `COPY` (`0x1`) |
| Source operand kind | 5, address expression | 1, temporary/register |
| Eligibility return | 1 | 0 |
| Pointer reaches intervening-definition check `0x31a50` | Yes; returns 0 | No |
| Template pointer after `0x306c1` | Removed; ID load uses entry | COPY retained; ID load uses template |
| Heading base after `0x306c1` | Entry | Template |

The disassembly of `0x309bb` directly checks for opcode `0x12` at RVA `0x309c3`
and returns zero for other opcodes. For an eligible LEA it then checks the
address-expression kind and base temporary. The call/return observer confirms
that this exact opcode distinction is exercised. The canonical LEA/COPY pair
has been coalesced to a LEA defining the watched pointer when the predicate is
called; the retaining control reaches it as a COPY.

This explains **address retention** for a real source control. It does not
explain the native dead memory write or stack overlap. In particular, the
retained COPY's destination is still kind 1, not a materialized memory store.

## Pointer-copy and source-hypothesis controls

Ten new source/profile controls were compiled, plus the canonical baseline:

| Control | Result |
|---|---|
| Scoped scalar assignment, entry-relative or pointer-relative heading | Both reproduce baseline normalized instructions |
| Four-byte pointer-object `memcpy`, entry-relative or pointer-relative heading | Both reproduce baseline normalized instructions |
| The same two `memcpy` sources with `/Oi-` | Actual copy call remains; 123 instructions; 62.184874% / 63.025210% |
| Generic inline whole-spawn helper, `P` versus `const P &` bound to the pointer expression | Identical normalized instruction streams to each other; both regress to 65.789474%, 113 instructions, seven aligned references and one problem |
| Actual embedded four-byte ID object with an inline `get()`, direct access or pointer access | Both reproduce baseline normalized instructions |

The embedded-object test overlays the real entry field's declaration rather
than casting an existing integer object into a class. Compile-time checks
verify the four-byte ID object, 24-byte entry, heading offset 8, and ID offset
12. The repository's shared header is not edited. The generic helper preserves
the existing offset updates and repeated field reads.

The pointer-copy trace is a discriminating negative. At entry to global
optimization, it is opcode `0x16b`, with kind-2 source and destination operands.
That specific block-copy node is gone or scalarized by return from `0x130cb`.
The pointer reaches late lowering and cleanup as scalar definitions with
kind-1 destinations; it never takes dxdiag's demonstrated late memory-store
path. The normal four-byte `memcpy` therefore **does not exercise the proposed
late nonzero-store mechanism**. This is not a claim that every aggregate or
block-copy representation is equivalent.

Disabling intrinsics leaves a real call that reads the pointer's stack storage.
That write is live across the call, and is not the native dead-store pattern.
Neither `/Oi-` control is retained as a matching source or configuration.

## Verification and reproduction

The observer experiments use the pinned `msvc6.5 /O2 /GB /W3 /GR-` profile and
C2 SHA-256 `d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a`.
RVAs in this report apply to that binary.

For each of the six traced sources, `trace.py` verifies equality of normal,
captured, independently replayed, and observed **whole COFF objects**, excluding
only timestamp bytes 4–7. It compares function metrics, checks that frontend
streams remain unchanged, and rejects a withheld frontend stream without
accepting a stale object. The two additional decision traces independently
preserve the whole COFF and reproduce the same consumer findings. Runtime
addresses are compared only within their own replay, never across runs.

The phase observer redirects loaded call sites through trampolines that save
and restore flags and registers before invoking the original target. The
decision observer additionally preserves the original return path so it can
read the actual predicate result. It changes no compiler decisions, source
operands, or compiler files. Compiler patching is not a proposed match.

From the repository root:

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-timeline-consumers-2026-09-11/probes.py \
  --out /private/tmp/vc6-pro-probes
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-timeline-consumers-2026-09-11/mine.py \
  --out /private/tmp/vc6-pro-mine
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-timeline-consumers-2026-09-11/trace.py \
  --out /private/tmp/vc6-pro-verified
```

`results.json` records the six traced sources and asserted consumer/predicate
findings. `source-controls.json` records the ten new controls plus baseline;
`mined-controls.json` records all 98 rebuilt sources and their structural
observations. The output directories retain complete sources, objects,
disassemblies, serialized frontend streams, and raw traces for inspection.

The next missing evidence is a source-produced **dead pointer-valued memory
write**. The partial control now provides a measured address-retention example
against which to compare one. These tests do not establish original-source
identity, semantic completeness of the partial control, or a compiler ceiling.
