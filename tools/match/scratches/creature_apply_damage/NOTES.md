# `creature_apply_damage`

Native target: `crimsonland.exe` at `0x004207c0` (976 bytes).

Live Binary Ninja evidence recovers the complete damage-type perk pipeline,
the living-fortress player fold, bullet heading jitter and clamp, pre-dead
lifecycle acceleration, damage/impulse stores, lethal death handling, shock
burst template, and type-indexed death sound. The function returns whether
health is non-positive; the prior shared header's `void` prototype was wrong.

The recovered original `Crimson.h` identifies the fourth argument as a
`vec2_t force`, confirming that both adjacent floats are one vector. The
matching harness represents the VC6-lowered boundary as a
`const vec2f_t *impulse`; the function source and saved Binary Ninja prototype
now expose `impulse->x`/`impulse->y` while retaining the 89.87%, 237/237 build.
A matching shared-header declaration and authoritative name-map signature now
keep that vector type at every recovered caller and across Binary Ninja map
replay instead of reverting the boundary to `float *`.
A direct modern by-value reconstruction was also checked, but changed alias
analysis, lost one instruction, and regressed to 87.10%, so it is not retained
as a false claim about this compiler build.

The decrementing living-fortress timer pointer is required to reproduce the
native induction register. Its former `[-0x20]` access is the current player's
health field: recovering the containing `player_state_t` through
`offsetof(living_fortress_timer)` names that gate without changing any of the
237 generated instructions. A small value-type multiply for the lethal impulse
reproduces the otherwise unexplained x87 temporary and pop sequence. The shock
burst only overwrites flags, color, lifetime, half-size, and each particle's
rotation, velocity, and scale step; it deliberately leaves the remaining
global effect-template fields untouched.

The direct creature impulse stores now use `creature_t::velocity.x/y`, and the
shock burst uses `effect_template.velocity` and `half_extent` components.
These canonical aggregate members are byte-neutral: the candidate remains
`237/237` instructions at `89.87%`, with the same `80/0/0` reference audit.

Every perk gate in this function calls the exact `perk_count_get` helper, which
reads player 0 only. Both ports now preserve that native asymmetry when
`preserve_bugs` is enabled for Uranium Filled Bullets, Living Fortress, Barrel
Greaser, Doctor, Ion Gun Master, and Pyromaniac; corrected mode deliberately
keeps the co-op-wide perk policy. Once player 0 enables Living Fortress, the
subsequent timer fold still visits every configured player exactly as native.
The Python port now also rounds the incoming float arguments and every modifier,
Living Fortress scale, health subtraction, and impulse subtraction through the
shared x87 PC=24 helpers. A focused Barrel Greaser plus Doctor boundary differs
by 17 micro-units from host-double arithmetic and pins the native result.

Zig now owns the post-`creature_handle_death` branch here as well: ordinary
damage deaths consume the type-indexed death-sound draw, while shock-ranged
deaths instead consume the four exact caller-tagged draws five times and emit
the native 36-unit, 0.7-second armored burst. Direct Energizer, plague, and
no-corpse deaths no longer consume this damage-only follow-up.

Both ports now preserve the native lethal impulse boundary: the first impulse
is stored before `creature_handle_death`, while the doubled impulse is stored
after it. Split children therefore inherit only the first impulse; if allocation
reuses the source index, only that current record receives the post-handler store.

The natural VC6 reconstruction reaches 89.87% with exactly 237/237 normalized
instructions and 80/0/0 reference agreement. The remaining structural delta
is one exact 12-instruction ion-gun perk block: native block layout places it
after the shock-effect loop, while VC6 lays the equivalent `else if` block
beside the other damage-type handling. Natural `if`/`else`, inverted nesting,
and `switch` spellings were tested; none recover the native placement without
regressing code generation. A layout-only `goto` would be a fakematch and is
intentionally rejected.

## Recovery classification audit

Live Binary Ninja still places the equivalent Ion Gun Master branch at
`0x00420ad5..0x00420afc`, after the shock-effect arm, while the natural VC6
`else if` places the same 12-instruction block beside the other damage-type
handling. The remaining focused regions are consequences of that block
placement plus local register allocation; no call, condition, arithmetic
step, store, or reference is missing.

Classification is `RECOVERY=semantic-complete`, `RESIDUAL=compiler`. This is
byte-neutral: before and after are 89.87%, prefix 11/237, 237/237
instructions, and references 80/0/0.
