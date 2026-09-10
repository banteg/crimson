# Timeline template-pointer removal in VC6

The canonical `quest_spawn_timeline_update` still has **113/115 instructions**,
91.228070% normalized agreement, prefix 51, 13 clean aligned references, and
`body_byte_exact: false`. This record adds **zero source matches**.

The observer locates one concrete compiler transformation. The source's
`int *template_id = &entry->template_id` at `scratch.cpp:63` has a `LEA`
(`0x12`) and a `COPY` (`0x1`) in C2's instruction list. C2 records their
function-relative source line as 40. Both nodes survive `C2+0x30308`, then
disappear during **`C2+0x306c1`**, before global register allocation finishes
and before the forward allocation pass at `C2+0x336f4`.

| Observation boundary | Total IR nodes | Template-pointer nodes |
|---|---:|---|
| Before `0x30308` | 172 | `LEA`, `COPY` |
| Before `0x306c1` | 170 | `LEA`, `COPY` |
| After `0x306c1`, before `0x30a40` | 165 | absent |
| Before `0x336f4` | 155 | absent |

The verifier checks node identities as well as source lines: the original
nodes are removed, not merely relabeled. The pass removes other nodes too;
this record identifies only the two tied to the template-pointer definition.
The after-pass hook is reached directly after `0x306c1` returns, with only a
register move before the hooked call to `0x30a40`.

Native keeps a template pointer in EDI for the spawn arguments. It also
stores EDI to `[esp+0x10]`, immediately followed by a store of the zero spread
counter to that same slot. This trace does **not** establish how that native
home store was produced, nor that retaining these two candidate IR nodes
would reproduce it. It identifies the candidate's removal point so further
source investigation can inspect the actual transformation rather than
infer it from final register names.

## Reproduce

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-timeline-address-2026-09-10/verify.py \
  --out /private/tmp/c2timeline-proof
```

The runner uses the adjacent frontend-capture verifier and its existing
local VC6 runtime/import providers. It checks:

- Pinned canonical source and C2 hashes, compiler profile, and flags.
- Equality of normal, captured, replayed, and observed **whole COFF objects**,
  excluding only timestamp bytes 4–7.
- Rejection of a missing frontend stream without accepting a stale object.
- All four instruction-list snapshots, their counts, the two selected
  opcodes, and removal of the original node identities.
- Unchanged function metrics and continued failure of both exactness gates.

`observer.c` changes four loaded call displacements to preserving
trampolines. It reads instruction metadata and then invokes each original
callee; it does not alter operands, optimization flags, allocation
preferences, or compiler files. The whole-object comparison verifies that
the observer did not change this compilation's output. This is a bounded
observation of the pinned candidate, not evidence about the unavailable
original source or a limit on future source recovery.
