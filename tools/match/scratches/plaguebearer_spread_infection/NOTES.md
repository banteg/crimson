# plaguebearer_spread_infection

The recovered source preserves the native fixed-pool scan, strict 45-unit
distance test, first-hit return, and two-way infection propagation through
pool indices. All 14 masked references resolve to the intended pool fields and
constants.

The remaining mismatch is compiler shape, not a semantic approximation. The
native object retains one subtraction operand on the x87 stack while forming
the squared length and folds loop exhaustion directly into the zero-return
fallthrough. The clean inline distance helper emits a different equivalent x87
schedule plus two loop-control instructions. Keep this scratch WIP until a
plausible source abstraction explains both differences; do not force them with
assembly or artificial liveness.
