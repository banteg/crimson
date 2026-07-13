# bonus_spawn_at_pos WIP

Current best local score:

```txt
match=88.44% prefix=0/99 target_insns=99 candidate_insns=100 refs=14/0/0
```

The recovered source matches the native bounds and Rush-mode guard, slot
allocation, fixed 16-entry spacing scan, sentinel fallback, pickup field
initialization, random type selection, weapon selection, points jackpot roll,
and metadata default amount. All 14 masked references resolve to the intended
globals, constants, and helper calls.

Writing the squared distance as two source operations recovers the native x87
stack schedule through `fsqrt`. This also exposed a Python parity bug: native
PC=24 arithmetic rounds one reachable boundary hypotenuse to exactly 32, while
the old double-precision squared-distance predicate treated it as below 32 and
rejected the spawn. Both ports now use the explicit native PC=24 hypotenuse.

The remaining mismatch is register-save placement. Native saves `EDI` at entry
and shrink-wraps the `ESI` save until after the early guard; the calibrated VC6
compiler saves both registers in the prologue for this clean source. The body
otherwise aligns instruction-for-instruction after accounting for the shifted
save/restore sites. Do not distort the source to manufacture the register
schedule without compiler or neighboring-object evidence.
