# Muzzle-flash vector ownership

The muzzle offset now writes its cosine and sine components directly into the
existing `render_delta` vector. This reproduces native's entry-relative homes
at -16 and -12. The small-flash draw now subtracts a two-component quarter-size
vector, reproducing native's float spill before subtraction. The preceding
source used a separate offset temporary and a scalar quarter-size value.

Normalized alignment rises from **94.947735% to 97.431432%**, gaining
**113.803002 fuzzy-weighted bytes** and leaving a **117.691772-byte** weighted
gap. The candidate has **1,149 instructions** against native's **1,148** and
all **333 audited references** are clean. The nine-instruction prefix and both
whole-function exactness flags remain unchanged. This is a partial instruction
recovery; no additional exact function or matching native link is claimed.

## Native instruction and machine evidence

[verify.py](verify.py) checks two complete instruction spans, offsets
`0xd31..0xe71` and `0xe8e..0xf91`, against the native function at `0x428390`.
All **145 instructions** in these spans agree in normalized operands, byte
size and offset. The ordinary masked-reference audit remains enabled.
[native-current.diff](native-current.diff) retains the full residual diff,
including the intervening load-scheduling difference, shield scheduling,
living-body argument homes, and targeting-line addressing/scheduling.

The unchanged parent fixtures and guarded machine runner compare **851
native/before/current cases**. Every case agrees on ordered call arguments,
permitted global writes, targeting-line distance bits, and full player and
creature storage. The 239 original call hashes are checked again. All 2,553
observed runs preserve x87 control word `0x037f` and an empty x87 stack; 753
additional controls compare the observer against the ordinary runner on all
returned fields. [results.json](results.json) records the program identities,
parent hashes, instruction spans, observed stack homes and per-case hashes.

The current source restores **22 previously mismatched stack accesses** and
displaces none of the preceding proof's unambiguous pairs. Three additional
native accesses now pair unambiguously: the quarter-size spill, the camera-Y
sum store, and the subtraction's memory operand. All three agree. This raises
the observed pairing count from 199 to **202**, removes the preceding single
ambiguous pairing, and reduces mismatches from 26 to **four**. Those four are
the unchanged living-body width/height argument stores and loads at native
function offsets 2165, 2175, 2522 and 2532. Three non-frame EBP accesses remain
explicitly excluded from stack-home accounting.

The source before this change is [before.cpp](before.cpp), SHA-256
`df048c95f7ba8cd30ab5b8ac3a4a9ad1ab46b658eea1ff7b6a6e3b1ae24fef2b`.
The retained source SHA-256 is
`93a5f988ea28855eb588ce1fa6c6b687ee70c8d8b939b0ac70e592c7bcc98e98`.
Native image SHA-256 remains
`771531fe72c36dbcb7ca8d8a391f00884ced8240fbb17080ffc3e0e59482c4f4`.

## Compiler observation and source controls

Fresh stock-C2 [before](stack-before.json) and [current](stack-current.json)
traces use the preceding package's unchanged read-only observer. Both have
45 allocation symbols, 43 checked local descriptors, seven allocation groups
and a 44-byte frame. The scoped model predicts every descriptor home. Normal,
captured, replayed and observed COFF objects agree within each source build
except for timestamps. Missing-stream, truncated-trace and corrupted-offset
controls remain active. Compiler data and binaries are not modified.

The existing `render_delta` allocation gains six uses, from 14 to 20, while
keeping its -16 home. Direct component writes avoid the four copy instructions
observed when assigning a constructed vector to this existing owner in the
preceding [dead-body controls](../overlay-dead-body-size-2026-09-11/README.md).
Native evaluates cosine before sine; that component order is retained.
The changed lifetimes also place the muzzle position temporaries at their
native homes. These traces explain candidate emission, without establishing
unique original variable names or lexical scopes.

[source-controls.json](source-controls.json) retains seven reconstructible,
hash-checked controls, reproduced by [verify_controls.py](verify_controls.py)
and [control-results.json](control-results.json):

- Direct XY/YX assignments to the old offset owner and to `render_delta`.
  Old-owner XY is neutral; old-owner YX loses alignment. `render_delta` XY
  reaches 96.515679%, and YX reaches 96.167247%.
- Three quarter-size vector forms on the improving XY control: a fresh local,
  component writes to the retired offset, and assignment to that offset.
  All reach 97.431432%, 1,149 instructions and 333 clean references. The fresh
  local is retained because it directly expresses this draw's size.

The final proof covers the combined source. These controls are bounded
observations, not exhaustion claims.

## Scope and reproduction

The unchanged parent explicitly models Grim2D recording callbacks, perk
queries and D3DX normalization. It executes native CRT float conversion, but
not the external graphics/audio backends. These PC=64 fixtures establish no
PC=24, arbitrary-input or pixel equivalence. No runtime bug is demonstrated in
the preceding source by these cases. No matcher normalization, reference alias,
waiver, Python gameplay or Zig gameplay changes are part of this recovery.

```sh
uv run --with unicorn==2.1.4 python \
  tools/match/evidence/overlay-muzzle-ownership-2026-09-11/verify.py \
  --out /tmp/crimson-overlay-muzzle-proof
uv run python \
  tools/match/evidence/overlay-muzzle-ownership-2026-09-11/verify_controls.py \
  --out /tmp/crimson-overlay-muzzle-controls
uv run python \
  tools/match/evidence/overlay-size-ownership-2026-09-11/verify_stack.py \
  --source tools/match/evidence/overlay-muzzle-ownership-2026-09-11/before.cpp \
  --out /tmp/crimson-overlay-muzzle-stack-before
uv run python \
  tools/match/evidence/overlay-size-ownership-2026-09-11/verify_stack.py \
  --out /tmp/crimson-overlay-muzzle-stack-current
```

The stock VC6 toolchain and Unicorn JIT permission are required locally.
