# `quest_build_lizard_raze`

Native target: `crimsonland.exe` at `0x00438840` (254 bytes).

Live Binary Ninja evidence recovers paired template `0x2e` lizard waves from
the right and left edge midpoints. Triggers begin at 1500 ms, advance by 6000
ms, and stop before 91500 ms; every wave has count six. The loop is followed
by three template `0x0c` alien spawners at `(128, 256)`, `(128, 384)`, and
`(128, 512)`, all at 10000 ms with count one. The final count is 33.

The retained source preserves the native base-plus-count record builder,
signed width-halving sequence, integer-to-float x87 conversions, 24-byte
record stride, loop boundary, fixed tail, and output count. Under the default
VC6 profile it matches all 254 bytes and all 77 instructions, with all three
constant references resolved.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, constant,
record-store, and output-count policy. The candidate is byte-exact, so no
recovery or residual classification is needed.

## Exact-tail follow-up (2026-07-27)

The five-compiler and six-flag matrices retain VC6 `/O2 /GB`; VC7 and `/G6`
regress, with the other tested VC6 spellings tied. A recorded 48-variant
source-order sweep retains only the explicit post-store tail increments,
raising weighted bytes from `201.22077922077924` to `204.51948051948054` and
reducing the gap from `52.779220779220765` to `49.48051948051946`. Five
helper-store permutations then all regress. At that checkpoint the candidate
preserved 77/77 instructions, a 16-instruction prefix, and `3/0/0` references.

## Exact boundary recovery (2026-07-30)

The exact `quest_build_lizard_zombie_pact` result exposed the relevant record
boundaries, and three bounded sweeps closed this adjacent function:

- `entry-boundary-transfer-mutations.json` tested 35 variants. Typed position
  pointers plus preserved old indices on both loop records moved the candidate
  from 80.519% to 89.610%, added 23.091 weighted bytes, and extended the exact
  prefix from 16 to 37 instructions.
- `left-loop-schedule-mutations.json` tested 13 variants. Direct indexed
  metadata fields, with the independent clock update before the count store,
  moved the candidate to 92.208% and a 65-instruction prefix. The two-field
  helper transfer was neutral and therefore falsified for this record.
- `final-tail-epilogue-mutations.json` tested 31 variants. Direct indexed
  fields on only the third fixed tail record closed the remaining 19.792
  weighted bytes; output-pointer lifetime variants were neutral.

The final source matches 254/254 bytes and 77/77 instructions, has a
77-instruction prefix, and resolves references 3/0/0. Five recorded experiment
entries cover 132 evaluated variants and one exact winner. Exact source
SHA-256: `d197bb88f40cc29b4bab6dca465cbcdbdeeebf130b426c6886f8205a5f54a239`.
Experiment ledger SHA-256:
`34bf9b30661131813f0e7eb248b0430483b354f9eb1be3660c7a19ebece12986`.

The retained changes are ordinary indexing, typed position boundaries, direct
record fields, and semantic reordering of independent stores. No volatile
state, dummy dependencies, forced registers, or compiler-profile exceptions
are used.
