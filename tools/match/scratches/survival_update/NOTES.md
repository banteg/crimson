# survival_update

High-value recovery for the 2,102-byte Survival-mode coordinator at
`0x00407cd0`.

Live Binary Ninja evidence identifies three coherent responsibilities: two
single-player emergency weapon handouts, level-gated scripted formations, and
the elapsed-time-driven random edge-spawn loop. The source keeps those phases
and their native mutable globals explicit while matching is refined.

The recovered candidate now covers the complete function: the console/demo
gate, both reward handouts, all ten scripted stage transitions, the signed
`500 - elapsed / 1800` wave interval, extra-spawn compensation, and both
four-way edge switches. A short-lived right-edge Y scalar is retained on x87
while X is evaluated, matching both native right-edge cases without an
ordering shim.

The recent-death mean is recovered as a short-lived vector of the same type as
the native three-entry global. Its two `operator+=` calls and component scaling
reproduce the complete native x87 window: X remains live while Y is rounded
through the stack after each addition and after the one-third scale. Live
Binary Ninja disassembly confirms those rounding points and the subsequent
distance/health reward test at `0x00407da5..0x00407e2f`. Both ports now express
the arithmetic through the shared PC=24 helpers; a boundary regression records
the native exact-16 result rejected by the strict radius test.

The current honest VC6.5 result is 98.21% with the exact 504-instruction count
and references `139/0/0`. The sole mismatch is the first three scripted spawn
calls. Native reuses the dead centroid slot at `[esp+0x10..0x14]`; this natural
separate-scope source assigns that spawn vector to `[esp+0x18..0x1c]`, then
realigns with native from stage 2 onward. A shared vector recovers the native
slot but forces VC6.5 to materialize centroid X, while returned-vector chains,
independent scalars, and alternate lexical scopes all produce less plausible
or materially worse code. The residual is recorded rather than hidden with a
union, volatile state, alias tricks, dummy expressions, or artificial
dependencies.

The random edge-spawn phase now passes each stack position as a complete
`const vec2f_t *` to the shared `survival_spawn_creature` contract rather than
taking the address of its first float member. Binary Ninja confirms that
prototype at `0x00407510` and identifies the stack locals as vector aggregates.
The change preserves the honest 98.21% score, exact 504-instruction count, and
all 139 references.

The recent-death reward distance now also reads player zero through
`player_state_t::position`. The aggregate field spelling is byte-neutral at
98.21%, 504/504 instructions, a 102-instruction prefix, and 139/0/0
references.

## Recorded centroid/spawn lifetime search

`centroid-spawn-lifetime-mutations.json` exhaustively evaluated 79 single,
pair, and triple lifetime combinations spanning shared versus dedicated outer
vectors, centroid representations, and the first scripted spawn temporary.
No valid variant improved the 98.21% baseline: natural shared/dedicated and
renamed forms are byte-neutral, while scalar/plain forms regress or fail to
compile when combined incompatibly (spec
`90ba4a354d983edcc00f75723e265e90a7744a3f08bc9ad34a93ac99e1616eac`).
The full result, including compile-invalid interactions, is recorded in
`experiments.jsonl`.

## Recovery classification audit

The focused diff has the exact native 504-instruction count and confines every
remaining mismatch to the first three scripted spawn calls. Live Binary Ninja
identifies the same `vec2f_t` call arguments and shows native reusing the dead
centroid slot; the natural separate-scope source uses a later stack slot, then
realigns for all remaining stages and both random edge-spawn loops. No
condition, formation, RNG call, coordinate, or reference is absent.

Classification is `RECOVERY=semantic-complete`, `RESIDUAL=compiler`. Before
and after classification remain 98.21%, prefix 102/504, 504/504
instructions, and references 139/0/0.
