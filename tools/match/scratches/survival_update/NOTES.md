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
four-way edge switches. The scoped position vector reproduces the native
`0x48`-byte frame and its later stage/loop slot reuse. A short-lived right-edge
Y scalar is retained on x87 while X is evaluated, matching both native
right-edge cases without an ordering shim.

The current honest VC6.5 result is 98.22%: 504 target instructions versus 506
candidate instructions, with references `134/0/1`. Every mismatch is confined
to the recent-death centroid window. Native code keeps the X accumulation live
on x87 while rounding the Y component through the reusable vector slot; VC6.5
materializes the first X sum in this source and reloads it, adding two
instructions. Constructor, returned-vector `operator*`/`operator-` chains,
in-place scaling, and direct independent scalar sums were checked; all produce
less plausible code or materially worse matches. The residual is recorded
rather than hidden with volatile state, alias tricks, dummy expressions, or
artificial dependencies.
