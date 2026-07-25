# fx_spawn_secondary_projectile

Verified local score:

```txt
match=100.00% prefix=65/65 target_insns=65 candidate_insns=65 refs=13/0/0
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

The final stack-frame match comes from ordinary source lifetime. Keeping the
semantic `angle`, trail reset, and `type_id` assignments after the direction
calculations leaves both scalar arguments live while VC6 schedules their
independent field stores ahead of the x87 multiplies. It can reuse the dead
`pos` argument slot for the cosine, but must reserve one genuine four-byte
local for the sine. This produces native's leading `push ecx`, both saved
direction components, and the exact store order without volatile storage,
unused expressions, or other register constraints.

The input is now recovered as a read-only `vec2f_t *` in both source and the
saved Binary Ninja prototype at `0x00420360`; the helper reads `x` and `y` but
never mutates the caller's position. The type correction preserves the exact
65/65 instruction match and all 13 references.

The allocated record now receives that value through
`secondary_projectile_t::position`, and seeker targeting passes the canonical
`player_state_t::aim` vector directly. Both aggregate recoveries remove scalar
aliases/casts while preserving the exact body.
