# Secondary rocket body rounding

The rocket, seeker-rocket, and rocket-minigun body branches now subtract their
half-size **before** the color call. The preceding source stored both components
of `camera_offset + position` across that call, rounding X too early. Native
keeps X extended through subtraction while explicitly rounding the Y sum first.
The three original `draw_pos -= ...` statements are moved; constants, calls,
compiler flags, and reference aliases are unchanged.

At native `0x42588c..0x4258dd`, `0x425906..0x42595d`, and
`0x42598f..0x4259e6`, the checked instruction windows contain the same ordering:
load/add X, load/add Y, store Y, subtract X half-size, store X, reload/subtract Y,
store Y, then call `grim_set_color`. There is no intervening call or X-sum store.
This establishes the native rounding boundary without identifying a unique
original C++ spelling.

Three independent float oracles distinguish the corrected X from the old X:

| body | native and corrected X bits | preceding source X bits |
| --- | --- | --- |
| Rocket, 14px | `0x4159c911` | `0x4159c910` |
| Seeker rocket, 10px | `0x40d74881` | `0x40d74880` |
| Rocket minigun, 8px | `0x415bb43f` | `0x415bb440` |

The oracle evaluates native X as `float32(camera_x + x - half_size)` and Y as
`float32(float32(camera_y + y) - half_size)`. The finite binary32 fixture values
fit the intermediate sums exactly in binary64. Each X also differs from the
premature-store control `float32(float32(camera_x + x) - half_size)`.

## Machine verification

`verify.py` compiles the current source and links its COFF relocations, then
compares complete native/candidate caller traces and modeled state for **1,194
fixtures**. They include all six tested secondary type values (0–5), active and
inactive entries, slots 0/1/31/63, both glow settings, multiple transition alphas,
mixed pools, the three pinned rounding cases, and 300 seeded finite geometries.
The number, order, and sizes of body/glow quads have independent oracles. The
secondary layout and type IDs are checked by compiling the shared header.

Three separately compiled arm reversions and the exact preceding source each
fail at their corresponding rounding fixture: **six rejected controls**, each
with one wrong X argument and all other call arguments unchanged. `before.cpp`
preserves the preceding source at SHA-256
`3b5c5cb097ebcf0cf298758ccefbf370202dcc41068f5808e99c9db503afb986`.

`replay_regressions.py` checks all **1,502** preceding plasma, beam, ion-chain,
and laser fixtures against the corrected candidate. It reads the four immutable
historical receipts, verifies the native image/body identities and each recorded
native trace hash, then requires the newly compiled candidate to reproduce that
trace. The receipts retain their original source identities; `regressions.json`
records the current replay separately. The earlier standalone verifiers also
accept `--source` so their original negative-control recipes remain replayable
against `before.cpp`.

`historical-replay.json` records a fresh successful run of those four standalone
commands against `before.cpp`, including all 1,502 fixtures and 40 rejected
historical defect cases. The historical receipts themselves are unchanged.

The runner records Grim thiscall arguments, uses explicit effect/perk stubs,
executes machine x87 and native `crt_ftol` under control word `0x037f`, and checks
stack balance, callee-saved registers, allowed instruction addresses, and absence
of non-stack writes. Secondary, primary, player, and creature state hashes agree.
These are caller-behavior fixtures under the documented external-call models,
not GPU/pixel identity or all-input equivalence. The Python and Zig ports use
centered sprite helpers; no port float-bit identity is claimed or changed here.

## Source controls and matching

`source-controls.json` preserves **23** reconstructible source controls:
seven direct-subtraction combinations and four variants each of four assignment
boundaries. All compile; the complete compound-before-color form both corrects
the tested behavior and gives the strongest alignment with unchanged reference
debt. Direct and vector subtraction also fix the tested argument bits but have
weaker alignment and more reference problems. `verify_controls.py` rebuilds the
recorded edits from the pinned preceding source and checks every recorded result.

| measurement | before | after |
| --- | ---: | ---: |
| normalized alignment | 59.622514% | 60.323887% |
| fuzzy-weighted bytes / 12,551 | 7,483.221773 | 7,571.251012 |
| candidate / native instructions | 2,913 / 3,021 | 2,907 / 3,021 |
| resolved / unresolved / mismatched references | 464 / 0 / 10 | 466 / 0 / 10 |
| normalized or encoded exact | false | false |

The gain is **88.029239 fuzzy-weighted bytes**. The instruction count moves six
farther from native; the correction is retained for the independently observed
native operation boundary, not as a count improvement. All ten positional
reference mismatches remain visible. No new whole-function match, waiver, or
normalization change is introduced. Recovery remains incomplete.

## Reproduce

Run from the repository root with local Unicorn JIT permission:

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/secondary-body-rounding-2026-09-11/verify.py \
  --out /tmp/secondary-body-proof
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/secondary-body-rounding-2026-09-11/replay_regressions.py \
  --out /tmp/secondary-body-proof
uv run --no-sync python \
  tools/match/evidence/secondary-body-rounding-2026-09-11/verify_controls.py \
  --out /tmp/secondary-body-controls
```

`results.json`, `regressions.json`, and `controls.json` pin the relevant source,
verifier, engine, native image/body, object, relocation, fixture, and build
identities. Generated native executables and scratch controls stay outside the
tracked evidence package.

These commands describe the source revision pinned by this package. After the
[conventional-corner correction](../conventional-corner-rounding-2026-09-11/README.md),
that package's `replay_regressions.py` verifies all 1,194 secondary fixtures
against the new canonical source while preserving this receipt and its native
trace hashes.
