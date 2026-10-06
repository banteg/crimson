# Roadmap

Prefer one wasm32 recovered simulation artifact for browser, Workers and a
desktop host. Keep Python for fast iteration and experiments. Extend the
recovered C/C++ for the shipped game and verifier rather than maintaining
another independent mirror. Keep native clang as a diagnostic comparison target;
avoid expanding its 64-bit layout machinery before trying a real client on
the shared WASM artifact.

## Gates

1. **Original rules.** Every Rush, Survival and Quest fixture in full plus a
   fixed bot corpus agree with Python's complete `RunResult` under
   `preserve_bugs=True`, including the input schemes, settings and players they
   need. [`checks/gate.py`](checks/gate.py) runs it in CI. Done for the
   supported scope; Typ-o support remains.
2. **Ranked rules.** Python's documented fixes run in the core behind a runtime
   policy flag; both policies pass the gate, and default-policy Python replays
   verify. Done: 142 of 142 streams agree, the eight human recordings included.
3. **Rules definition.** Done: [ranked rules](../docs/rewrite/ranked-rules.md)
   define the boards, the pinned profile, human controls, the 1024x768 aim
   bound, finite inputs, command order, UI pause and timing, versioned by
   `game_version`. Python verification enforces them; the service applies the
   same checks.
4. **Client.** The whole recovered game, including menus, options, high scores
   and the perk screen, runs in the same module as the verifier.
5. **Service.** Server-owned run configuration, score and terminal policy,
   public replay decoding, and measured dense/adversarial workloads and
   deployed Workers CPU.

## Zig retired

The independent Zig port was retired once the core passed the gate under both
bug policies; the last commit that has it is tagged. The core still uses the
Zig 0.17.0 compiler and its bundled math as build dependencies.

## Original-rules gate

The gate feeds identical input and command streams to both implementations:
recorded fixtures and a fixed bot corpus covering all 50 quests and varied
seeds, perks, weapons, aim schemes and run settings. Separate bot decisions
must never conceal a divergence. It compares the full result defined in
`src/crimson/sim/run_result.py` (outcome, elapsed time, kills, shots fired and
hit, RNG state, pending perks, quest final time and each player's experience,
health as F32 bits and most-used weapon), the terminal tick and outcome, and
per-tick state to locate the first divergence.

Still to do: report bot quest completion and failure coverage separately. Runs that exhaust their budget are incomplete, not
terminal coverage.

When Python and the core disagree, reduce the first divergence and use the
original executable through Unicorn to decide the original behavior. For an
intentional modern rule, check the documented rule instead. Fix Python when the
original evidence shows it is wrong; keep the reproducer and update the
reference rather than weakening the comparison.

## Ranked rules

Ranked runs use `preserve_bugs=False`. Each documented Python fix the core's
scope reaches is a patch in `patches/`, applied to the generated copies at the
native site behind the policy flag, so RNG call order matches Python under both
policies, and `decomp/` stays untouched. A new Python fix needs its patch and a
bot scenario that exercises it under both policies. Treat the policy as part
of the server-owned rules; the same input stream under different policies need
not give the same result.

Fixes still only partly exercised by the corpus: Shock Chain or a seeker with
no creature left (20), a bonus carrier's death handled twice (33), and an
exact-zero Highlander hit (18).

## Evidence and limits

Native/WASM agreement proves modern-build determinism. The new original-code
tests establish selected x87 seams, and the quest-builder oracle establishes
table construction. Neither establishes whole-run original equivalence.

The Wasmtime probe runs the identical Node/Worker module from Python and
compares every snapshot hash and reset across all scenarios. This makes the
desktop embedding proposal concrete for simulation. A rendered client still
needs an output/event ABI and measurements of memory access and host calls.
One compiled module removes cross-target layout/compiler variation; it does
not make undefined C++ behavior safe or establish original-game correctness.

When live play and verification use the identical module and rules, a small
difference from the original is a fidelity question rather than a disagreement
between the client and verifier. Shared rule bugs can still be exploited with
chosen inputs. Keep rule validation and sampled original comparisons; do not
make exhaustive whole-run original equivalence a product release gate. The
original executable is the fidelity oracle; the portable build must still earn
its agreement with it.

## Define floating-point state and hash behavior

The [WASM specification](https://webassembly.github.io/spec/core/exec/numerics.html#aux-nans)
allows variation in NaN signs and, for noncanonical operands, payloads outside
its deterministic profile. Running the same module in V8 and Wasmtime does not
alone guarantee identical raw NaN bits. Do not rely on an engine-specific
canonicalization setting for a browser/Workers contract.

Inventory non-finite values in the authoritative schema during the full-run
and bot gate. Reject non-finite input as today, and make an unexpected
non-finite value in a field required to be finite a deterministic simulation
error. If an intentional NaN sentinel is needed, define its bit representation
at the producing boundary and in snapshot/hash serialization. Ensure payload
bits never influence gameplay via integer reinterpretation. Canonicalizing
only a hash must not conceal invalid authoritative state.

## Client milestone: the whole recovered game

Use the same WASM module for the full recovered game: gameplay, menus, options,
high scores and the perk screen. The host supplies real Grim rendering, input,
audio and persistence imports. Live input reaches the exact normalized tuple
and command seam used by the headless verifier.

Recovered update/render routines include simulation cleanup and RNG effects,
so keep those effects on every authoritative tick. Collect a draw-command list
per tick and present the latest completed list after the host's zero-to-many
tick batch; reuse the last list when no tick runs. Run menu presentation frames
while gameplay is paused, without advancing authoritative time or consuming
authoritative RNG except through the defined semantic commands. Test this
clock split and command behavior through the actual client.

Audit import return values and writes rather than treating all Grim calls as
draw-only. Text metrics and menu geometry must support recovered interaction;
resource IDs need a stable contract. The headless host may discard presentation
outputs only once the authoritative dependencies are understood.

## Preliminary stub audit

| Boundary | Observed dependency | Consequence |
| --- | --- | --- |
| Omitted menu layout / perk prompt | `perk_prompt_bounds_*` alias vertices of `ui_perk_prompt_element`; its initial data is zero. `ui_menu_layout_init` normally creates the geometry and origin. `perk_prompt_update_and_render` changes timer/rotation and draws it. | The original click-prompt path cannot work with the headless geometry. Commands are the intentional menu seam here. Restoring only the prompt draw function would not repair it. |
| `game_state_set` | The original resets UI, pause, current/previous state, transition and input. The core stores only the pending state. | This is a session-policy replacement, not a harmless draw stub. Native menu-frame equivalence requires a separate audit. |
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
choice bounds enforced by the core. The README records the core's
offer-generation behavior, including picks without an explicit menu request.

This seam is compatible with the Python session model by design. It is not a
claim that original perk-screen frames were RNG/time neutral. Before defining
a public rules version, test command order and UI pause/resume through a real
client using precisely the verifier's core and canonical inputs. `.rsi` remains
private and contains no submitted score.

## Grow the original-code differential

Grow this alongside concrete full-run discrepancies and the client stub audit;
a differential harness for every translation unit is not a prerequisite for
the next product gate. Start with stateful player, projectile, creature, perk
and bonus routines using states sampled from Rush, Survival and quest runs.
The math oracle demonstrates direct calls into the original x87 code without
substituting the Python implementation for Normalize.

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

The current hash/count guards are appropriate for now. They are not the
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

Keep one pinned implementation of the portable numerical helpers owned by the
recovered core, with original x87 oracle cases as its regression contract. The
current CRT power duplication is temporary. Document bypassing screen-to-world aim conversion
as part of the modern rules definition, not just a numerical parity fix.
