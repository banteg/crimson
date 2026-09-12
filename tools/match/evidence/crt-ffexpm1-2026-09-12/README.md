# VC6 `__ffexpm1` exact native extent

The pinned VC6 SP6 `libcmt.lib` member `87tran.obj` recovers native
`crt_ffexpm1` at `0x00464e4e..0x00464e91`: **24/24 instructions,
67/67 relocation-aware encoded bytes, and 2/0/0 references**.

The existing raw IDA manifest independently names this 67-byte function
`__ffexpm1` and the next function `_isintTOS`. The archive's public
`__ffexpm1` symbol starts at `.text+0x15e` and extends across subsequent
private helpers. `ARCHIVE_SIZE=67` selects the native extent through its
return. The verifier rejects inclusion of the next helper's first instruction.
No compiler, matcher, or extent-acceptance rule changes.

The previously unnamed `fld tword` operand at native `0x00464e52` reads
`0x0047b67e`. All ten bytes agree with the archive's static `_log2max` at
`.data+0x1e`: `000000000000ffff0d40`. The data map now records this original
symbol identity as `crt_x87_log2max`, and the native data inventory retains
its explicit ten-byte extent and initializer. This is binary provenance,
not a claim of an independently reconstructed C initializer.

The helper retains its native branch into neighboring CRT code. The existing
positional reference audit checks that destination; the prefix does not earn
credit for the neighboring or trailing helpers. This adds one archive-backed
native match outside the portable gameplay scope. The source-built decomp.dev
code score does not gain these 67 bytes.

Reproduce from the repository root:

```sh
uv run --no-sync python tools/match/evidence/crt-ffexpm1-2026-09-12/verify.py \
  --out /private/tmp/crt-ffexpm1-proof
uv run --no-sync crimson match scratch tools/match/scratches/crt_ffexpm1 --scope all
```

The receipt pins the archive, member, executable, native manifest, selected
body, constant, configuration, and verifier hashes. Four negative controls
reject extra helper bytes, a changed return opcode, an unproven constant
identity, and a changed constant byte. These are static identity checks,
not a new floating-point execution test suite.
