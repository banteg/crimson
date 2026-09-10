# Player/projectile call-boundary audit

The current original and candidate bodies were compared by static call identity,
then the discrepancies were checked against native instructions and source.
This inventory is not a dynamic trace or a semantic-equivalence proof.

| Function | Native calls | Candidate calls | Finding |
| --- | ---: | ---: | --- |
| `projectile_update` | 125 | 125 | Every direct call identity agrees in linear instruction order. Arguments and paths still require separate evidence. |
| `player_update` | 182 | 183 | One extra `fx_spawn_sprite`; no missing callee. Native shares the second Shrinkifier/Pistol smoke tail. |
| `projectile_render` | 180 | 180 | The candidate has one fewer color site and one extra quad site; static counts alone do not identify dynamic differences. |

Direct call keys use resolved native addresses, not printed analyzer names.
Indirect keys preserve displacement while masking only the register name; they
are operand shapes, not proof of receiver or vtable identity. The full count
tables and native head-call window are in `comparison.json`.

## Renderer: recovered post-head color reset

Native executes `grim_set_color` at `0x00424aae`, `grim_draw_quad` at
`0x00424af3`, and the same color publication again at `0x00424b11`. The latter
pushes the saved head alpha from EDI, then 1.0, 0.6, and 0.5, through vtable
offset `0x114`. The source now includes that second publication before the
projectile-type gate and arc processing.

[`verify_head_color.py`](verify_head_color.py) checks the unique straight-line
window in both machine bodies. It verifies identical RGB bits and the same
callee-saved alpha register across the two publications, the 32px quad size,
resolved Grim receiver loads, and the absence of intervening register writes
or branch entries. The [receipt](head-color.json) records the source, verifier,
image, object, body, and build identities. Removing the reset, changing its
RGB, and changing its alpha each compile and are rejected by the verifier.
This is local operation proof; head position, upstream alpha computation,
whole-renderer behavior, and full-function exactness remain outside it.

The exact, encoded-body-verified Grim implementations show that set-color
publishes all four color slots, while draw-quad consumes those slots without
changing them. Its begin/flush helpers also do not reset those slots. Under the
shipped renderer's ordinary synchronous operation, the second publication
therefore appears redundant. No changed pixels or port rendering correction
are established by this evidence.

At the September 9 baseline, the correction restored eight instructions but moved stack homes throughout
the function: **59.194040% becomes 58.200879%**, **2885 becomes 2893** of 3021
instructions, and references **456/0/10 become 452/0/12**. Both normalized and
encoded-body exactness remain false. The two added reference mismatches pair
native 10.0 strip multipliers at `0x00424c71`/`0x00424c7e` with candidate 4.0
widening multipliers; the existing ten mismatches persist. The source retains
both widths and the matcher continues to report the disagreements.

The September 9 correction's regression exception was scoped to its original
base. The subsequent [small-plasma alpha correction](../plasma-head-alpha-2026-09-10/README.md)
updates the current candidate and regression receipt. The head-color verifier
continues to require the same machine window and reject all three source
defects. Its whole-function reference comparison now reports added and removed
pairings instead of requiring the unrelated historical 10/12 mismatch counts.
The regenerated receipts describe current inputs; the preceding score change
is historical.

The earlier 24 head-call/alpha controls and the further 99 combinations of
side/start/end strip-copy boundaries do not remove the regression. Four
initial combinations redeclared `width`; renaming the end-strip local made
all 99 compile, with at least 11 mismatches each. No strip variant is retained.
These finite controls bound the tested source forms, not future recovery.

## Player and projectile update boundaries

The player discrepancy is the previously documented shared smoke tail:
native `0x0041612a` branches to `0x0041600e`, where both paths push the
second sprite's position and call `fx_spawn_sprite` at `0x0041600f`. The current
candidate retains separate calls. The existing scoped-vector probes already
cover the obvious ownership changes and regress; the live call inventory does
not supply new evidence for another arbitrary scope rewrite.

`projectile_update` preserves all 125 linear direct call identities. That
rules out a simple missing/extra direct-call explanation of its current gap;
it does not certify operands, branch predicates, memory lifetimes, or gameplay.
The prior native jitter, decal, and tint boundaries remain local partials.

The authenticated vector SDK and the separately reproducible
[`vector-return-contract-2026-09-08`](../vector-return-contract-2026-09-08/README.md)
controls still admit both explicit output-buffer and hidden value-return helper
forms. The helper controls were rerun successfully. Neither exact helper bytes
nor a synthetic matching caller identifies the original large caller's source
contract. No helper signature or global vector layout is changed.

## Reproduce

```sh
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/call-boundaries-2026-09-09/verify.py \
  --out /private/tmp/crimson-call-boundaries
UV_CACHE_DIR=/private/tmp/crimson-uv-cache uv run --no-sync python \
  tools/match/evidence/call-boundaries-2026-09-09/verify_head_color.py \
  --out /private/tmp/crimson-head-color
```

This checks the current source and bodies, verifies the native call window,
and recompiles the four inspected Grim callees to normalized and encoded-body
exactness. It does not loosen matcher acceptance or classify a finite experiment
family as exhausted.
