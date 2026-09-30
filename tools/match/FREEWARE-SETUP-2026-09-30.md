# Freeware matching bootstrap, 2026-09-30

Builds 1.0.2, 1.3.0 and 1.4.0 now have generated maps for their original
`crimson.exe` and `grim.dll`, with the image SHA-256 pins from
`decomp/builds.json`. Each image explicitly names its 1.9.93 mapping donor;
these builds remain outside the 1.9 source family.

The mapper excludes heuristic entry candidates inside verified function bodies.
The freeware CRT exposed this problem: an aligned interior of `crt_ehvec_ctor`
was being named `crt_fpmath` in 1.0.2/1.3.0, and an interior of
`crt_lcmap_string` was being named `crt_msize` in 1.4.0. The maps retain the
complete verified body and discard those interior candidates. A regression
checks both exact and interface-equivalent extents.

## Compiler baseline

`uv run crimson match build-scan <build> -j 6 --json` compiles mapped source
scratches with `msvc6.5` and the build's own `CL_BUILD`. It skips archive and
import-thunk candidates. Counts below are source comparisons, including mapped
initializers and any library source scratches; they are not whole-game progress.

| Build | Image | Match | Audit | WIP | Error |
|---|---|---:|---:|---:|---:|
| 1.0.2 | crimson.exe | 17 | 0 | 61 | 0 |
| 1.0.2 | grim.dll | 166 | 8 | 66 | 0 |
| 1.3.0 | crimson.exe | 21 | 0 | 89 | 0 |
| 1.3.0 | grim.dll | 179 | 7 | 42 | 0 |
| 1.4.0 | crimson.exe | 57 | 4 | 90 | 0 |
| 1.4.0 | grim.dll | 195 | 5 | 39 | 0 |

`Match` requires normalized positional instructions and resolved references.
It does not assert linked-executable recovery or encoded-body equality for
every row. `Audit` has a complete instruction score but unresolved or differing
reference evidence; it earns no match credit. A placement-only map row earns
no compiler credit.

The single-scratch path also passed for `console_clear_log --build 1.4.0`:
28/28 instructions, an encoded-body exact result, and resolved references.
The comparison targets `crimson.exe` at `0x00401940`, using its own function and
data maps rather than the donor's native addresses.

## Validation and next work

The matching, report, data-report and native suites passed (190 tests), Ruff and
ty passed, and a fresh `build-map --check` verified all committed maps.

The original bootstrap used partial donor maps and did not publish percentages.
The follow-up adds independent native discovery, reviewed ownership clusters,
and a full executable-byte denominator; see
[the reporting policy](../../analysis/decomp/README.md#freeware). All 183, 200 and
252 original source matches also pass the encoded-body check with the retained
native extents. The maps and compiler baseline support recovery of changed
bodies with `scratch --build` and `probe --build`.
