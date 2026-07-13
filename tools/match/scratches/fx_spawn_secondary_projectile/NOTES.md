# fx_spawn_secondary_projectile WIP

Current best local score:

```txt
match=84.38% prefix=0/65 target_insns=65 candidate_insns=63 refs=13/0/0
```

The recovered source matches the fixed 64-entry pool scan, full-pool fallback,
shot counter, projectile initialization, seeker target selection, and all 13
masked references.

The velocity expressions preserve the native x87 shape. The angle subtraction
stays on the FPU stack and is duplicated for `fcos` and `fsin`; assignment
expressions save float copies of the direction while retaining each trig result
for the initial 90-unit multiply. Seeker rockets later reload those saved float
copies for the 190-unit override. Although the subtraction is not explicitly
spilled, gameplay runs with x87 precision control at 24 bits, so the Python and
Zig ports correctly model it as a PC=24 subtraction before evaluating trig.

The remaining mismatch is a single stack-allocation slot. Native reserves one
four-byte local in the prologue, while the calibrated compiler reuses argument
space for the saved cosine and allocates no local. The meaningful FPU sequence
and field stores otherwise align. Do not introduce a volatile or unused local
solely to manufacture the native frame.
