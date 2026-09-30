# Direction after the feasibility spike

Prefer one wasm32 recovered simulation artifact for browser, Workers and a
desktop host. Keep Python for experiments and the existing Zig verifier until
the client, rules version and correctness gates are ready. Keep native clang
as a diagnostic comparison target; avoid expanding its 64-bit layout machinery
before trying a real client on the shared WASM artifact.

## Evidence and limits

Native/WASM agreement proves modern-build determinism. The new original-code
tests establish selected x87 seams, and the quest-builder oracle establishes
table construction. Neither establishes whole-run original equivalence.

The first legacy divergence was a movement trig spill before the first PC24
multiply. Correcting Normalize also removes a later heading difference. CRT
power now matches the existing PC24 model and original thresholds. The other
fixture aim differences were caused by the host's world/screen/world round
trip; original x87 agreed with both calculations when supplied their operands.
Canonical world aim now reaches gameplay without that conversion.

The Wasmtime probe runs the identical Node/Worker module from Python and
compares every snapshot hash and reset across all scenarios. This makes the
desktop embedding proposal concrete for simulation. A rendered client still
needs an output/event ABI and measurements of memory access and host calls.
One compiled module removes cross-target layout/compiler variation; it does
not make undefined C++ behavior safe or establish original-game correctness.

## Preliminary stub audit

| Boundary | Observed dependency | Consequence |
| --- | --- | --- |
| Omitted menu layout / perk prompt | `perk_prompt_bounds_*` alias vertices of `ui_perk_prompt_element`; its initial data is zero. `ui_menu_layout_init` normally creates the geometry and origin. `perk_prompt_update_and_render` changes timer/rotation and draws it. | The original click-prompt path cannot work with the headless geometry. Commands are the intentional menu seam here. Restoring only the prompt draw function would not repair it. |
| `game_state_set` | The original resets UI, pause, current/previous state, transition and input. The spike stores only the pending state. | This is a session-policy replacement, not a harmless draw stub. Native menu-frame equivalence requires a separate audit. |
| `grim_measure_text_width` | Among selected bodies it is called in the bonus hover label. Its result changes label placement; the nearby-bonus return and hover timer are determined independently. | No simulation dependency found in that selected call. Other UI functions use text widths for interaction, so this does not justify a universal zero stub. |
| `grim_get_texture_handle` | Recovered reset stores the result in six creature type records. Creature rendering passes it to texture binding. | Resource IDs differ and are excluded from canonical snapshots. This needs a resource/output contract for a real client; there is no complete stub noninterference proof yet. |

Next, compute read/write closure through aliases and indirect calls, then use
original memory traces and perturbation tests to identify stubs whose results
or omitted writes can affect authoritative state, RNG, commands or transitions.
Static xrefs alone cannot prove that a device stub is harmless.

## Make the replay seam deliberate

Keep the existing normalized F32 tuple and semantic command batches. Gameplay
ticks are fixed 60 Hz; menu UI frames do not advance gameplay time. Apply
ordered commands before the next tick, with entitlement, offer freshness and
choice bounds enforced by the core. The README records the current spike's
offer-generation behavior, including picks without an explicit menu request.

This seam is compatible with the Python session model by design. It is not a
claim that original perk-screen frames were RNG/time neutral. Before defining
a public rules version, test command order and UI pause/resume through a real
client using precisely the verifier's core and canonical inputs. `.rsi` remains
private and contains no submitted score.

## Grow the original-code differential

Start with stateful player, projectile, creature, perk and bonus routines using
states sampled from Rush, Survival and quest runs. The targeted movement oracle
is the first sampled-state example; the math oracle demonstrates direct real
x87 calls without substituting the Python implementation for Normalize.

Use `NativeOracle.trace_memory()` for original read/write sets and compare
canonical written fields and RNG against the compiled functions. `data.py`
provides symbol locations, but a global image cannot simply be copied: native
64-bit pool strides differ, and even wasm32 pointers, function addresses and
heap references need relocation. Add typed state/argument serialization and
explicit dependency/environment contracts. Expand snapshot coverage where a
routine reads state absent from the current diagnostic schema.

Track tested routines, states and branches, not only the 168 translation units;
a unit can contain multiple functions and helpers. Then grow toward the full
orchestration, including initialization and the selected modern session policy.

## Retire generated regex adaptations deliberately

The current hash/count guards are appropriate for the spike. They are not the
long-term maintenance model. Move proven numerical operations and input seams
into named source abstractions that preserve the historical compiler's exact
expansion while providing modern implementations. A generic `X87_WIDE` cast
alone is insufficient: first-operation rounding, exponent range, F32 spills and
CRT helper behavior are separate properties.

Gate that migration on actual historical compiler/object matching and the
original-code differential for each affected target. Keep adaptations for
different original versions explicit. Do the source migration after the
correctness contracts are established, without turning the adapter into another
independent simulation implementation.
