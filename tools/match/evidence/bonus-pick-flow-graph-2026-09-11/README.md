# Bonus selection flow-graph comparison

The retained source is still **not byte exact**: 75.925926%, 162/162
instructions, prefix 55, and 20 resolved reference instructions. No scratch,
compiler configuration, reference alias, or matching rule is changed here.

## Positive evidence

`verify.py` freshly compiles the canonical source and follows both instruction
graphs from their entries. It treats direct unconditional jumps as transparent
edges, then requires a one-to-one mapping of every other instruction. Conditional
edges remain ordered as taken and fall-through; their conditions cannot be
inverted or their destinations exchanged. Every masked reference is checked
using the matcher's existing operand-owner rules at its graph-mapped location.

The result covers all **156 non-jump instructions**, all **six unconditional
jumps on each side**, and **20 reference instructions**. Register operands,
stack operands, non-address constants, calls, returns, and conditional decisions
agree under that mapping. Three negative controls separately change a condition,
a branch destination, and a reference owner; all are rejected.

This supports the diagnosis that the current machine-code discrepancy is block
placement and its required branches. It does not recover the original C++
spelling, grant encoded-body credit, or change the matcher's normal accounting.
The proof concerns the decoded instruction graphs and resolved static operands;
it is not a general C++ equivalence checker.

The same verifier freshly compiles `dsound_restore_buffer` as a positive compiler
control. That function is normalized and encoded exact. Its ordinary `do` loop
leaves `test eax, eax` after a backward jump following `Sleep(10)`. Consequently,
this compiler can produce an outlined loop condition. This does not establish
that the bonus selector's stage-5 predicate came from the same source construct.

## Additional source controls

`source-controls.json` records 29 reconstructible controls against the pinned
canonical source. These supplement the earlier 166 controls in
`../bonus-pick-cold-edge-2026-09-11/`.

| Family | Count | Observation |
| --- | ---: | --- |
| Nested retry loops | 8 | 169 or 170 instructions; changed register allocation |
| Duplicated filters with size-oriented options | 21 | 152–248 instructions; no exact result |

The second family tests `/Os`, `/O1`, and `/O1 /Ot` on two full duplicated-tail
forms and five duplicated-prefix forms. Size-oriented compilation merges code
but loses the desired stage-5 placement and changes the sequence. Restoring the
speed preference retains additional instructions. These are bounded negative
results, not proof that no source spelling can match. Experimental sources are
recorded for inspection; their compilation is not itself a behavior proof.

## Reproduce

Run from the repository root:

```sh
uv run python tools/match/evidence/bonus-pick-flow-graph-2026-09-11/verify.py \
  --out /tmp/bonus-pick-flow/results.json
uv run python tools/match/evidence/bonus-pick-flow-graph-2026-09-11/verify_controls.py \
  --out /tmp/bonus-pick-flow/controls
```

`results.json` records the graph mapping, reference owners, rejected negative
controls, sound-loop positive control, and input/build hashes.
`control-results.json` records a fresh successful replay of all 29 source/option
controls, including their exactness flags. Both normal and encoded exactness
remain false for the bonus selector.

The reusable `crimson match scratch ... --flow-graph` diagnostic is independently
checked against this verifier's complete mapping, jump coverage, and reference
counts. Its opt-in JSON retains the ordinary match result and failure exit code.
Across all 810 port targets, it completes 709 exact-function graphs and this
one WIP graph. Nine WIPs report differences; 90 exact functions and one WIP
use unsupported flow or lack complete entry-reachable coverage. No supported
exact function reports a graph difference. These diagnostic results grant no
additional match credit.
