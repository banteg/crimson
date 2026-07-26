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

The position input is now a read-only `vec2f_t`, so the recovered guard,
spacing scan, and entry initialization use named `x`/`y` fields instead of raw
float offsets. The saved Binary Ninja prototype and a recovered
`bonus_entry_t *scan` induction cursor expose both the position and bonus-pool
fields in HLIL. This type-only change preserves the score and all 14
references.

The entry initialization also copies through the canonical
`bonus_entry_t::time.position` aggregate. The aggregate assignment compiles
identically to the two scalar component stores, preserving the 88.44% WIP.

The spacing scan now reads that same aggregate on every owning bonus record,
removing its last `time.pos_x`/`time.pos_y` compatibility aliases. The result
remains 100/99 instructions, 88.44%, and 14/0/0 references.

The remaining mismatch is register-save placement. Native saves `EDI` at entry
and shrink-wraps the `ESI` save until after the early guard; the calibrated VC6
compiler saves both registers in the prologue for this clean source. The body
otherwise aligns instruction-for-instruction after accounting for the shifted
save/restore sites. Do not distort the source to manufacture the register
schedule without compiler or neighboring-object evidence.

Inverting the guard into a valid-position body does not induce shrink-wrapping:
VC6 still saves both registers in the prologue and also changes the floating
comparison forms, reducing the score to 80.40% with two fewer aligned
references. The native-facing invalid guard remains the stronger source shape.

## Recovery classification audit

Live Binary Ninja HLIL accounts for all bounds, spacing, allocation, sentinel,
initialization, random-type, weapon, jackpot, and default-amount paths. The
candidate emits 100 instructions against 99 native instructions with `14/0/0`
references. Its localized differences are the documented saved-register
lifetime and dependent allocation/scheduling only, so recovery is
`semantic-complete` with a `compiler` residual.
