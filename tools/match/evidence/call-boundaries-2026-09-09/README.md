# Player/projectile call-boundary audit

The current original and candidate bodies were compared by static call identity,
then the discrepancies were checked against native instructions and source.
This inventory is not a dynamic trace or a semantic-equivalence proof.

| Function | Native calls | Candidate calls | Finding |
| --- | ---: | ---: | --- |
| `projectile_update` | 125 | 125 | Every direct call identity agrees in linear instruction order. Arguments and paths still require separate evidence. |
| `player_update` | 182 | 183 | One extra `fx_spawn_sprite`; no missing callee. Native shares the second Shrinkifier/Pistol smoke tail. |
| `projectile_render` | 180 | 178 | Two fewer color-call sites in aggregate. Branch merging contributes; a specific native head-color reset is also absent from source. |

Direct call keys use resolved native addresses, not printed analyzer names.
Indirect keys preserve displacement while masking only the register name; they
are operand shapes, not proof of receiver or vtable identity. The full count
tables and native head-call window are in `comparison.json`.

## Renderer: omitted post-head color reset

Native executes `grim_set_color` at `0x00424aae`, `grim_draw_quad` at
`0x00424af3`, and the same color publication again at `0x00424b11`. The latter
pushes the saved head alpha from EDI, then 1.0, 0.6, and 0.5, through vtable
offset `0x114`. Only then does it test projectile type and query arc targets.
The current fading-ion source has the first color call and head draw, followed
directly by the type gate. The second color call is absent.

This is a native-operation recovery gap, not evidence of a visible rendering
bug. The exact, encoded-body-verified Grim implementations show that set-color
publishes all four color slots, while draw-quad consumes those slots without
changing them. Its begin/flush helpers also do not reset those slots. Under the
shipped renderer's ordinary synchronous operation, the second publication
therefore appears redundant. No port gameplay/render change is justified by
this finding alone.

The complete 3-control head-call/type-reload family, 17-control live/fading
alpha interaction family, and 4-control head-alpha ownership family all compile.
Restoring the call adds eight instructions but moves stack homes throughout the
function: 59.194040% becomes 58.200879%, with references 456/0/10 becoming
452/0/12. Const-reference, repeated-expression, and existing-life ownership tie
that result; reusing fade is worse. Branch-local and call-expression loop alpha
controls recover separate static calls but do not improve the whole candidate.
No source or alias change is retained. These 24 controls do not establish that
the native call cannot be recovered without regression.

The scratch is marked incomplete with an analysis residual because a known
native operation is absent. Compiler-only source recovery is no longer an
adequate description, even though no changed pixels have been demonstrated.

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
```

This checks the current source and bodies, verifies the native call window,
and recompiles the four inspected Grim callees to normalized and encoded-body
exactness. It does not loosen matcher acceptance or classify a finite experiment
family as exhausted.
