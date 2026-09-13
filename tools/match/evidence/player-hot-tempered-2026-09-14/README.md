# Hot Tempered ring and Fire Cough receiver

Two source changes recover native `player_update` behavior and code structure:

- Give Hot Tempered's odd/even projectile types separate call branches. VC6
  merges the common argument construction and call, retaining native's
  conditional `push 9` / `push 11` and EBX loop counter. The previous ternary
  generates arithmetic type selection instead.
- Subtract the jittered aim through the reselected Fire Cough player's position.
  Native reselects the player after the two sound calls and uses its position
  in EBX as the `vec2_sub` receiver at `0x413b7f`.

Neither exactness flag is true. The original 16,257-byte target extent, aliases,
compiler flags and matching scope are unchanged. This is not a newly proven
port bug: before and after agree with native in the bounded fixture model.

## Local ring proof

Native `0x413cca..0x413d0e` (exclusive) and candidate `0x613..0x657`
contain the same 24 instructions in 68 bytes after auditing three positional
external references: the current player index, the float angular step and
`projectile_spawn`. Only their actual four-byte COFF relocation fields are
masked. All other bytes, including branch displacements, agree. The four local
branches land on the same relative instruction boundaries.

Full-function ESP propagation reaches every instruction, has no conflicting
join depths and balances both returns. The region starts 88 bytes below entry
ESP; every paired instruction has the same depth. Corrupting the parity mask,
projectile type, branch displacement or call reference makes the region checker
reject the comparison. This bounded region check does not change full-function
acceptance or count as a newly exact function.

| Native matcher measurement | Before | Retained |
| --- | ---: | ---: |
| Candidate instructions / native 4,206 | 4,068 | 4,070 |
| Prefix | 7 | 7 |
| References: clean / unresolved / mismatched | 805 / 0 / 2 | 807 / 0 / 2 |
| Instruction ratio | 64.00774% | 64.49976% |
| Normalized / encoded exact | false / false | false / false |

The complete branch/receiver interaction is retained. Receiver alone produces
798/0/4 references; branch form alone produces 805/0/2. Their combination
recovers the native ring and receiver without increased reference debt. The
extra receiver-only mismatches remain the later perk alignment artifact
documented in the [preceding evidence](../player-fire-cough-2026-09-14/README.md).
No reference waiver is used.

## Execution and negative controls

`controls.json` reconstructs the baseline at `55c36d4d8` and thirteen controls:
five angle value/field/reference forms, four ring/receiver forms, receiver alone, two
color-store forms, and a source-line shift. Only `hot-branches-receiver-True`
is retained. Direct color stores grow the stack reservation from `0x48` to
`0x4c` and disturb allocation; neither is selected. By-value vectors introduce
extra copies without recovering the angle sequence. Binding the angle expression
to a const reference restores the early store, but reverses X/Y loads and drops
`fxch`, as the field-store control does. Its clean references fall to 797, so it
is not retained. VC6 rejects the non-const reference version with C2440.

`execution.json` binds before/after source and body hashes to the actual
3,827-case native execution result and its pinned runner dependencies. Native,
before and retained machine code have equal ordered modeled calls and final
observed state in every case. The native observation digest agrees with the
prior point-frame proof. Coverage is 4,198/4,206 native instructions; the eight
unvisited instructions are listed in the receipt. The layout probe also passes.

Movement, heading, vector helpers and CRT conversion execute native code;
input, RNG, sound, effects, allocation, reload and damage callbacks are modeled.
This proves those cases under gameplay x87 PC=24 and those callback models,
not whole-game equivalence or hypothetical callbacks mutating player selection.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/player-hot-tempered-2026-09-14/verify.py \
  --out /tmp/player-ring-proof --all-controls --trace
```

Use a new output directory. `--controls-only` skips machine-code execution;
`--trace` independently repeats preserving compiler traces. The verifier expects
the retained canonical source at this revision; use this checkout after later
matching changes. `results.json` records the rebuilt controls, stack maps and
region checks. `execution.json` is the separately completed execution receipt.

## Angle scheduling and C2 line labels

The angle source at file line 295 appears as C2 line label 171, relative to the
function definition at line 124. Adding seven blank lines before the function
moves those file lines to 302/131 while every observed C2 line/opcode sequence
and comparison signature remains unchanged. Both traces preserve the whole
COFF object and reject the missing-stream control. `trace-results.json` retains
the manifests, file anchors and extracted order; raw trace artifacts are
regenerated by `--trace`.

At phase 0, before `C2+0x130cb`, the angle intrinsic is node 362, before the
position Y/X additions at 368/370. At phase 1, before `C2+0xfcda`, those adds
are 334/336 and the angle intrinsic is 345. The scalar has been folded into
its later call use; the arithmetic is already delayed before allocation.
The pointer-add node sharing line 173 is explicitly excluded by the recorded
floating-node flag. No arena pointer is treated as continuous identity across
snapshots.

The earlier field-store control keeps the angle early but reverses its returned-
vector loads and removes native's `fxch`. That is still not a recovered sequence.
These traces narrow the transformation and correct the CLI's misleading
absolute-source-line wording. They do not identify the sole causal compiler
branch or reveal the unavailable original source.
