# Why the dxdiag stores survive while the timeline pointer disappears

The same stock VC6 build reproduces both observations without changing its
generated object: the redundant dxdiag zeroing stores survive, while the
timeline template-pointer definition disappears. This comparison identifies
different lowering paths, not a source match for the timeline function.

## Measured pass boundaries

`dx_get_version_from_dxdiag` source lines 73–77 correspond to C2 relative
lines 18–22. The zeroing starts as intrinsic opcode `0x190` plus three argument
definitions. The following four field assignments start as `0x15b` nodes.

| Boundary | Dxdiag zeroing | Following dxdiag field assignments | Timeline pointer |
| --- | --- | --- | --- |
| Before and after global pass `0x130cb` | One intrinsic | Four assignments | Address calculation and assignment |
| Before lowering `0x29511` | One intrinsic | Destination kind 1 | `LEA` and assignment, destination kind 1 |
| After lowering `0x29511` | Zero seed plus four `COPY` nodes, destination kind 2 | Four `COPY` nodes, destination kind 1 | `LEA` and `COPY`, destination kind 1 |
| Before `0x26d75` | Same four memory stores | Still destination kind 1 | Pointer nodes present |
| After `0x26d75` | Same four memory stores | Destination kind 2 | Pointer nodes present |
| Before and after `0x306c1` | Same four memory stores | Same four memory stores | Both pointer nodes removed |
| Before forward allocation `0x336f4` | Same four memory stores | Same four memory stores | Pointer nodes absent |

Here kind 2 denotes the symbol-backed memory operand; kind 1 is the
register/temporary representation. Kind 1 is not proof of a final physical
register: the dxdiag fields temporarily use it with C2's placeholder home
`C2+0xae040`. Their conversion back to kind 2 occurs inside `0x26d75`.

The observer verifies that each zeroing store and its following field assignment
refer to the **same destination symbol**, even while their operand kinds differ.
It checks all four zeroing stores against the common zero seed, then follows
the same node identities and destination symbols through the later passes.
The timeline checks also follow identities, so disappearing source-line labels
alone cannot satisfy the removal assertion.

## Interpretation supported by the compiler code

The intrinsic is expanded after the global optimization stage. The lowering
driver `0x29511` dispatches through `0x29b6e` and `0x29c3c`; opcode `0x190`
selects `0x2a495`, a trampoline to the intrinsic handler `0x54cc8`.

The copy cleanup called later within `0x29511`, at `0x2a632`, requires opcode
`1` and destination kind `1`. Its gate at `0x2a64c` returns immediately for
destination kind `2`. Thus the newly expanded zeroing stores do not enter
that cleanup. At this point the later field assignments still have a different
operand representation. Once both groups are memory stores, the observed
remaining passes leave them in the final byte-exact object.

The timeline instead reaches `0x306c1` with a derived address and a copy into a
kind-1 temporary. That routine analyzes kind-1 temporary definitions and their
uses; it removes both selected pointer nodes. It is not a general cleanup of
the kind-2 stores seen in dxdiag.

This establishes a concrete distinction between the candidates. It does not
establish how the unavailable original timeline source produced its pointer
home store, or that adding zeroing/copying to the reconstruction is justified.

## Reproduce and verification

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-store-pass-comparison-2026-09-11/verify.py \
  --out /private/tmp/vc6-store-proof
```

[verify.py](verify.py) pins both canonical source hashes, the C2 hash, and the
compiler profile. It reuses the frontend capture/replay verifier, including its
missing-stream negative control. [observer.c](observer.c) redirects twelve
loaded callsites through register/flags-preserving observers, reads instruction
metadata, and invokes the original callees. It does not change compiler files,
operands, flags, or optimization decisions.

For **both functions**, normal, captured, replayed, and observed whole COFF
objects agree except for timestamp bytes 4–7. [results.json](results.json)
records every measured boundary, source hashes, and metrics:

- Dxdiag: **100%, 190/190 instructions, 12 clean references, body byte-exact**.
- Timeline: **91.228070%, 113/115 instructions, prefix 51, 13 clean references,
  body non-exact**.

## Focused source follow-up

[source_controls.py](source_controls.py) tests twelve implicit pointer-wrapper
copy forms: POD or converting constructor; implicit copy initialization,
assignment, or an inline helper returning by value; and entry-based or
pointer-relative heading access. Unlike the earlier explicit copy-constructor
controls, these leave member copying to the compiler. Each source has a pinned
hash in [source-controls.json](source-controls.json), which also records the
baseline. Run with `--out /tmp/vc6-pointer-copy-controls.json` to reproduce.

All twelve compile successfully and retain the baseline score, instruction
count, prefix, and clean references. None is body byte-exact. These are bounded
source controls. No canonical source or compiler configuration change is
retained, and no new exact function is claimed.
