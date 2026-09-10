# Creature-death allocation observation

**This record claims no new source match.** It isolates an allocation decision
that is sufficient to reproduce the complete native death-handler body in a
diagnostic run. Canonical source, compiler binaries, flags, and match acceptance
remain unchanged.

| Input | Instructions | Exact prefix | References OK / problems | Normalized | Encoded body |
| --- | ---: | ---: | ---: | ---: | --- |
| Canonical source | 205 / 204 | 6 | 85 / 0 | 89.486553% | false |
| Pointer-first member read, normal compiler | 204 / 204 | 5 | 80 / 1 | 79.411765% | false |
| Same member source, observation only | 204 / 204 | 5 | 80 / 1 | 79.411765% | false |
| Same member source, diagnostic preference override | 204 / 204 | 204 | 87 / 0 | 100% | true |

The tested source change is only:

```diff
-    int creature_flags = creature_pool[creature_id].flags;
     creature_t *creature = &creature_pool[creature_id];
+    int creature_flags = creature->flags;
```

Both reads still precede the first conditional call. The normal compiler folds
the byte scale into the address operands for this form, but chooses EDX for the
second index LEA. It then chooses EAX, ECX, and EDX for the first two `movsx`
arguments and the bonus position address. Native instead uses EAX for that LEA
and EDX, EAX, and ECX for those following temporaries.

## Observer and counterfactual

The observer hooks the call at `C2.DLL+0x385b4` to the forward register selector
at `+0x3c97c`. Its trampolines preserve registers and flags. It records all 17
local selections, including the incoming preference, unavailable-register mask,
chosen register, and shared preference-list cursor before and after the call.
The observed object is identical to normal compilation across the **entire
COFF object**, excluding only header timestamp bytes 4–7. This checks sections,
relocations, symbols, and auxiliary records as well as the function body.

The counterfactual is built separately and explicitly marked
`compiler_state_modified: true`. At the second LEA only, it writes the EAX
symbol into temporary 449's preference field (`temp+0x2c`), then lets the
original selector run. It neither returns a fabricated register result nor
changes the selector's code. This preference avoids advancing the shared
cursor: it stays at EDX for the following argument loads. The resulting normal
backend output has 204/204 positional instruction identity, all 87 references
resolved without disagreement, and relocation-aware encoded-body identity.

That establishes the **sufficiency of one allocation change**, not the original
source or a unique explanation of the native compiler's decision. The modified
compiler state is not eligible for match credit. Reference counts differ
between rows because alignment differs; they are not independent discoveries
of new native references.

The source and C2 binary are pinned by SHA-256. The counterfactual checks the
temporary's opcode, source line, empty preference, empty exclusion mask, and
single application. The verifier also checks the trace length and first five
temporary identities and allocations. Changes to these inputs require a fresh
assessment rather than silently applying the override elsewhere.

## Reproduce

From the repository root:

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/vc6-death-allocation-2026-09-10/verify.py \
  --out /private/tmp/c2death-proof
```

The verifier uses the adjacent frontend-capture/replay harness. It captures
both canonical and member-first sources, verifies normal/wrapped/replayed COFF
equality for each, and rejects a missing-stream replay after removing stale
output. It then builds the observer and counterfactual independently. Generated
executables, objects, streams, and traces stay in the selected output directory.
The checked-in `results.json` records source, toolchain, native-body, and COFF
hashes plus the complete allocation observations.
