# A source-produced dead pointer store

**The missing instruction pattern is reproduced by stock VC6. The function is
still not matched.** A byte loop copying a two-pointer object leaves a write of
the unused copied member, immediately overwritten by spread's initialization.
The live pointer uses a different compiler operand. This supplies a concrete
alternative to interpreting the native write as a spill of the live pointer.

Canonical source and flags remain unchanged: 113/115 instructions, 91.228070%,
prefix 51, 13 clean references, non-exact body. No witness is installed as a
candidate, checkpoint, provider, or recovery claim.

## Positive source witness

The smallest successful control in this set replaces the pointer declaration
with the following block and reads heading through `((float *)template_id)[-1]`:

```cpp
int *template_id;
{
    pointer_pair selected;
    selected.last = &entry->template_id;
    selected.first = selected.last;
    pointer_pair copied;
    for (unsigned int k = 0; k != sizeof copied; ++k)
        ((unsigned char *)&copied)[k] = ((unsigned char *)&selected)[k];
    template_id = copied.last;
}
```

Here `pointer_pair` contains `int *first; int *last;`. Both pointers are
initialized; unsigned-character access copies their object representation.
This is a diagnostic source construction, not evidence that the game used
this object or copy routine. The unused member is intentional in the witness.
There is no volatile access, inline assembly, or compiler intervention.

[witness.cpp](witness.cpp) retains the exact generated source bytes, and
[witness.asm](witness.asm) retains the matcher-normalized listing. It emits:

```asm
lea edi, dword [esi+0xc]
mov dword [esp+0x10], edi
mov dword [esp+0x10], ebx
```

EBX is zero at this point. No instruction separates the two writes; the
pointer value in that slot is dead. Heading and ID are read through EDI.
The source SHA-256 is
`5ad0be6a087969c28411fe3658c58a1dd2863f4611f4e843d684210f0a257cf9`.

| Control | Instructions | Agreement | Prefix | Clean refs |
|---|---:|---:|---:|---:|
| Canonical | 113 | 91.228070% | 51 | 13 |
| Scalar pointer copied by byte loop, copied pointer used | 114 | 82.096070% | 14 | 12 |
| Pair initialized with two address expressions, last member used | 120 | 39.148936% | 1 | 8 |
| Pair initialized by copying one pointer value, last member used | 115 | 71.304348% | 1 | 12 |

All four have zero aligned-reference problems and non-exact bodies. The
115-instruction witness still reserves 32 stack bytes instead of 28, leaving
a four-byte gap before the vector locals. Its zero-register sharing and count
tests also differ. Equal instruction counts do not establish a match.

## Verified lowering history

[verify_trace.py](verify_trace.py) observes three stock compilations using the
existing complete-operand observer. Normal, captured, replayed, and observed
whole COFF files agree except for timestamp bytes 4–7. Captured streams retain
their hashes, and withholding a required stream rejects replay without an
output object. The pinned C2 hash is
`d50100ac2380d58f3f6f756961fb1319d35f5248e5fa6cafb866ca657e5dda4a`.

1. The initial IR contains the byte loop. Global optimization inside
   `C2+0x130cb` replaces it with copy intrinsic `0x190`.
2. Lowering inside `0x29511` expands the pair copy into two memory load/store
   pairs. Both destinations are kind 2, the symbol-backed memory form.
3. Inside `0x26d75`, the used destination becomes kind 1, a temporary. The
   unused destination stays kind 2. The scalar-copy control has only one
   destination, which becomes kind 1 and leaves no memory write.
4. The unused pair store keeps its node identity and destination symbol through
   every remaining snapshot, including after `0x306c1` and before `0x336f4`.
   No source operand references that destination symbol in those snapshots.
   Its source is eventually the register temporary carrying the derived pointer.
5. The final stock object contains the adjacent pointer/zero stores above.

The verifier follows identities and complete operand chains, not source-line
counts alone. Its assertions distinguish the unused memory destination from
the used destination that becomes a temporary. Runtime addresses are compared
only within their own replay. Full selected-node histories are retained in
[trace-results.json](trace-results.json).

This demonstrates a sufficient lowering route for the native pattern. It does
not identify the original source. In particular, the store can belong to an
unused member of a copy while EDI carries another, equal-valued member; it need
not be the live pointer's own stack home.

## Ablations and limits

[source_controls.py](source_controls.py) reproduces 119 variants plus a fresh
baseline. All 120 builds succeed; none improves canonical agreement or becomes
body exact. Forty-six variants reproduce baseline normalized instructions.
[source-results.json](source-results.json) records source/COFF/instruction
hashes, profile, native metrics, and the historical diagnostic screen output.

- Replacing the successful pair's byte loop with `memcpy` or ordinary assignment
  removes the witness and reproduces baseline instructions.
- Reading the original scalar pointer while copying it to one wholly unused
  scalar destination removes the entire copy. Keeping one used member of the
  aggregate is necessary in these tested controls.
- Two independently written address expressions and copying one pointer
  value both produce the dead store, but yield different surrounding allocation.
- Loop direction, comparison form, initialization order, scope placement, direct
  field use, and seven local-lifetime controls do not recover the missing frame
  layout and zero-register behavior.
- Aggregate copies with an unused integer/float zero can leave zero stores.
  Their pointer member still becomes a temporary; these are not pointer-store
  witnesses by themselves.

The legacy same-slot screen reports six false positives for split-byte pointer
copies: reads of bytes/words at offsets inside the earlier dword are missed by
its equal-start-address check. [audit_overwrites.py](audit_overwrites.py)
rejects all six using overlapping byte ranges and ESP adjustments, while
accepting the native adjacent-store control and the positive witness.
[overwrite-audit.json](overwrite-audit.json) retains both the candidates and
the rejecting reads. This is a conservative direct-frame check, not general
alias analysis. Historical screen output is preserved as diagnostic evidence.

The next source question is which actual aggregate copy or inlined copy loop
could leave an unused pointer-valued member without the witness's extra stack
extent. The positive control changes that question from an unexplained spill
to a reproducible late copy-expansion behavior. No source exhaustion is claimed.

## Reproduce

From the repository root:

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-timeline-pointer-home-2026-09-12/source_controls.py \
  --out /private/tmp/timeline-pointer-home-reproduction
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-timeline-pointer-home-2026-09-12/audit_overwrites.py \
  --root /private/tmp/timeline-pointer-home-reproduction \
  --out /private/tmp/timeline-pointer-overwrite-audit.json
```

Create the capture helper with the earlier
[counterfactual driver](../vc6-timeline-late-removal-2026-09-12/counterfactual.py)
using `--out /private/tmp/timeline-causal-proof`, if it is not already available.
Then run:

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-timeline-pointer-home-2026-09-12/verify_trace.py \
  --capture-dll /private/tmp/timeline-causal-proof/helper/capture.dll \
  --out /private/tmp/timeline-pointer-home-trace-proof
```
