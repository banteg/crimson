# Projectile stack-group observation

This observes the [frozen ownership candidate](../projectile-ownership-and-stack-2026-09-13/README.md)
without changing the installed compiler or canonical scratch. Ordinary, wrapped,
replayed and observed whole COFF objects agree except for their timestamps. A
withheld frontend stream, truncated trace and corrupted descriptor offset are
rejected.

The two preserved hooks are the existing pinned VC6.5 stack-coloring observation
points at C2 RVAs `33cde -> 4b617` and `5840f -> 34032`. The verifier uses the
[existing observer](../hud-stack-coloring-2026-09-10/observer.c) with the reusable
capture/replay helpers. It records 136 symbols and reconstructs 31 groups from
symbol order, sizes and directed conflicts, checking 97 named/generated
local descriptors and complete 232-byte storage coverage.

**Group membership is predicted; final placement is observed.** The HUD model's
ascending group-allocation order does not hold for this function. Applying that
assumption fails on the first descriptor. This verifier checks the actual
placement permutation for consistent members, disjoint intervals and complete
coverage; it does not claim to predict that permutation or original native
lifetimes. Candidate names are attached only where a compiler frontend ID can
be read unambiguously from the object-equivalent listing.

`primary_homes.py` propagates ESP through every native/candidate control-flow
join and return, accounting for the known D3DX stdcall pop. It checks the primary
prefix's paired instructions, internal branch destinations and explained
references, excluding its prologue allocation and stack displacements. It then
uses the checked listing to label individual native accesses with candidate
declarations. A shared native slot does not establish a shared source variable.

Selected observations use the steady frame base after local allocation and the
four saved-register pushes:

| Value or object | Native home | Candidate home |
| --- | --- | --- |
| Primary loop index | `0x1c` | `0x40` |
| Microstep index | `0x40` | `0x24` |
| Delta vector | `0x38` | `0x38` |
| Ion damage scale | `0x44` | `0xa8` |
| Primary effect color | `0x9c` | `0xb0` |

The delta now has one consistent native base across all 15 labeled accesses.
Previously, its four zero stores ran in the opposite component order; the
[chained-zero source step](../projectile-ownership-and-stack-2026-09-13/experiments.json)
recovers that order.

The observed candidate graph also explains two specific reuse decisions:
its two color objects share a 16-byte group, and its burst-direction temporary
`$T4658` shares an 8-byte group with the primary index. Native disassembly instead
places the secondary color at `0xf4`, and the burst cosine spill at `0x9c`
(`0x4223f0`, accounting for three pushed arguments). The native color buffer is
addressed at `0x421a58`. These differences motivate source-lifetime experiments;
they are not permission to pad or recolor storage. Moving the real secondary
color to function scope produces a `0xf8` frame, still non-exact.

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/projectile-stack-groups-2026-09-13/verify.py \
  --out /private/tmp/pu-stack-groups
```

The output path must be new and short. `results.json` records hashes, preservation
and negative-control receipts, graph membership, observed placement, and native
primary stack accesses. This diagnostic awards no function-match credit and
does not prove semantic equivalence. No compiler allocation data is modified.
