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
