# Native scalar content provenance

The preceding matcher accepted a read-only scalar constant in place of the
mutable native `bonus_freeze_timer` when their file bytes were both zero.
With an ordinary DIR32 relocation, both normalized and encoded-body checks
passed. The corrected matcher rejects that substitution. No additional
function match is claimed.

`verify.py` executes the matcher from commit
`dd9e4122083ab82d99dc383b066426bcfc8f5835` alongside the current matcher,
using the same function/reference catalog and pinned original executable.
It builds synthetic `fld` callers pointing at the real timer address
`0x00487018`, then substitutes either an anonymous read-only object or a
compiler floating constant. These are matcher counterexamples, not recovered
game functions or runtime execution tests.

Both substitutions are rejected. Three positive controls remain accepted:
the actual named mutable owner, a read-only float-pool reference, and the
existing compiler CString address-pooling rule. `results.json` retains all
caller bytes, relocation records, audited reference keys, outcomes, and input
hashes. The historical Python module is extracted into the reproduction
output directory; no historical compiler or repository checkout is modified.

Scalar content evidence now requires the entire operand width to be in a
readable, non-writable PE section. Base fixups, ordinary and delay import
slots, IAT directory ranges, and incomplete mapped data are excluded. Unknown
section provenance does not imply read-only storage. Tests use a generated
PE32 to check permissions, boundary overlap, loader writes, and rebasing.

CString reference pooling remains a separate existing policy: VC6 also puts
string literals in writable `.data`. It compares complete NUL-terminated
contents for addresses and loads from compiler-designated literal symbols,
excludes loader-written bytes, and
does not establish immutable storage or whole-program pointer identity.
It cannot justify arbitrary scalar memory loads from a writable object.

The stock `zlib_inflate_init2` is a live positive control: native instruction
`0x10047452` loads the first byte of `"1.1.3"` at `0x1005820c`. Its candidate
relocation identifies the complete compiler CString, rather than an ordinary
scalar constant. The verifier checks this real function with the current matcher.

Run from the repository root:

```sh
uv run --no-sync python tools/match/evidence/reference-content-provenance-2026-09-11/verify.py \
  --out /tmp/crimson-reference-content-proof
uv run --no-sync pytest -q tests/test_match_content_provenance.py tests/test_match.py
```

The port corpus retains 799/810 normalized matches and 797/810 encoded matches.
The two rejected synthetic cases are not part of those totals.
The refreshed all-scope report retains 1,271/2,437 matched functions,
380,689/718,801 matched bytes, and 371,132 encoded-body bytes. Both native
artifacts were rebuilt and verified as current with game-owned closure; their
structural links are not a runtime-equivalence claim. The full test run passed
2,996 tests and 135 snapshots, followed by the final targeted matcher and native
artifact checks.
