# Four-byte timeline pointer-store witness

Stock VC6 can emit the native pointer-store triplet with the native **28-byte
frame**. The earlier eight-byte copied object is no longer necessary to
demonstrate this behavior. This is a compiler mechanism result, not recovered
game source or an exact match.

The canonical scratch remains unchanged: **113/115 instructions, prefix 51,
13/0/0 references, 91.228070%, non-exact body**.

## A copied pointer whose only read disappears late

[witness.cpp](witness.cpp) copies one four-byte pointer through a byte loop.
Its copied value is read only by this guard, inside an existing positive-count
branch:

```cpp
if (copied != selected && entry->count <= 0) return;
```

The guard cannot return: no intervening operation changes the positive count.
The live template pointer is taken from `selected`, independently of `copied`.
The copy and redundant guard are intentional diagnostic constructs; there is
no evidence that the original game used them. They are not installed in the
candidate, native provider, or port.

The [stock assembly](witness.asm) contains the adjacent full-width stores:

```asm
lea edi, dword [esi+0xc]
mov dword [esp+0x10], edi
mov dword [esp+0x10], ebx
```

There is no intervening instruction or partial-width read. The same output
reserves 28 bytes and loads heading and template through EDI. Its remaining
[native diff](native-diff.txt) contains zero materialization/reuse, the resulting
branch displacements, and the y-coordinate add using `[edi-8]` instead of
`[esi+4]`. It has 115 instructions, prefix 14, 12 clean references, and
86.086957% agreement. It does not improve canonical agreement.

## The guard order changes when the copy becomes dead

[verify.py](verify.py) observes the pinned compiler without changing its
decisions. All three normal/captured/replayed/observed whole COFF comparisons
pass, excluding only timestamps. Missing-stream controls reject replay.
The verifier follows the byte-store destination's address definition to the
actual copied symbol, retains complete operand chains, and checks the emitted
body independently against the stock build.

| Boundary | Pointer comparison first | Count comparison first |
|---|---|---|
| After `C2+0x450d7` | Four-byte copy intrinsic exists; copied pointer is read | Same |
| After second `0x08f28` region | Copied pointer still read | Last copied-pointer read removed |
| After `0x06bd0` at callsite `0x13683` | Copy remains | Copy removed |
| After `0x43190` at callsite `0x136f2` | Last copied-pointer read removed; copy remains | Already removed |
| Across `0x29511` | Intrinsic lowers into an unused memory store | No copy to lower |
| Through pre-`0x336f4` | Same store node and destination symbol survive | No store |

The late removal at `0x43190` is observed directly with preserving entry/return
hooks. The copied symbol has no direct memory read after lowering. Its store
remains memory-class rather than being promoted to a temporary.

## Independent controls

Ten fresh stock builds are recorded in [results.json](results.json):

- Reversing the guard operands, deleting the guard, replacing the byte loop
  with `memcpy`, or using ordinary assignment reproduces the canonical body.
- Reading the copied pointer as the live template retains EDI but loses the
  dead store; its frame is still 28 bytes.
- A null-pointer predicate or an equality-to-zero count predicate reproduces
  the positive witness body. Pointer equality itself is not necessary.
- Moving the spawn counter before the outer loop and resetting it at the
  tail preserves the 28-byte frame, pointer triplet, shared EBX zero tests,
  and EBX/BL clears together. It remains non-exact: 115 instructions,
  76.521739%, prefix 8, eight clean references. Several register assignments,
  load ordering, and the y-coordinate base still differ.

These controls separate the native frame and zero-sharing requirements from
the earlier eight-byte witness. Remaining work is credible source recovery
and native register/scheduling choices. Adding the redundant guard to improve
a score would not recover the original source.

## Reproduce

From the repository root, choose a new output directory:

```sh
UV_CACHE_DIR=/private/tmp/crimson-match-three/uv-cache uv run --no-sync python \
  tools/match/evidence/timeline-four-byte-home-2026-09-13/verify.py \
  --out /private/tmp/timeline-four-byte-reproduction
```

The harness pins the canonical source hash, compiler profile, compiler hash,
and every extra callsite. Output includes all control sources, assembly,
native diffs, replay receipts, raw traces, decoded operands, and checked
transition summaries. Arena addresses are identities only within each replay.
