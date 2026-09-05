# `creature_apply_damage`

Native target: `crimsonland.exe` at `0x004207c0` (963 bytes).

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

## Recorded Ion-branch search

`ion-branch-shape-mutations.json` records four ordinary independent, nested,
split-test, and inverted-test spellings. VC6 emits the same 237-instruction
candidate at 89.87% with references 80/0/0 for every form. This confirms that
the native tail placement is backend block layout rather than evidence for a
different semantic branch.

## Compiler, outer-dispatch, and TU closure

A fresh live Binary Ninja bundle has SHA-256
`9a750f06ee021c9569072823441bd0e87d7314a2dc55b049e954656593f710e6`.
The normalized sequential diff confirms that target and candidate contain the
same 237 operations and operands. The sole structural difference is the
12-instruction Ion Gun Master arm: the candidate places it at object offset
`0x12e`, while native cold-splits it to `0x312` after the shock-effect loop.
The relocated block lengthens native branch encodings, explaining the
963-byte target versus the 949-byte candidate without missing behavior.

Compiler provenance is now exhausted across the available stock VC6 lineage.
Builds 8168, 8447, 8799, 8966, and 9782 all emit the byte-identical 89.87%,
237/237, `80/0/0` candidate. The Processor Pack and VC7 regress. A separate
22-cell VC6.5 flag matrix has 14 byte-identical ties and seven regressions;
the remaining `/Za` cell does not compile. No processor, optimization,
inlining, floating-point, frame-pointer, exception, string-pooling, COMDAT,
aliasing, or language-mode flag moves the Ion block.

The two previously untested complete outer dispatches are decisive
regressions. A sparse `switch` falls to 73.68%, 238 instructions, and
`68/0/2` references; placing the non-bullet arm first falls to 74.68%,
237 instructions, and `68/0/2`. Their recorded source hashes are
`0b2b96df0257ad4585fa0717201610f57d70ce7858c902fb626cec18e02531f0`
and
`b9f0ee6b7419e31647f289172b449b5e576689e0888be9142a85287a1699b99f`.

Translation-unit state is also bounded. Compiling the exact four-function
predecessor chain (`projectile_reset_pools`,
`creatures_apply_radius_damage`, `creature_find_in_radius`, and
`player_find_in_radius`) before this function is byte-identical. Compiling
the 8,409-byte `projectile_update` successor in the same unit is likewise
byte-identical. These recorded overlays have source hashes
`29d01109e5f7401ffc78396d07ad903ae207aa490f1eb8ddf5cb6202c7ad43a0`
and
`abfe3a397de343e4ed831e70a1f8ca00132604a3a08f3b6bc0dc6f6a335585af`.

The append-only five-record experiment ledger has SHA-256
`b1124df61bb6eb7d8064c5a7b40da4bb6ee00328fc2a96ac428b06fe61c18547`.
Further work should require new original-build block-order evidence rather
than another local branch spelling, compiler alias, or neighboring-function
probe.

## Exact perk and heading phases (2026-09-05)

The Ion Gun Master placement is source-structural, not an irreducible compiler
residual. Damage-type perk modifiers now form one phase; the bullet-only heading
change is a separate guarded phase immediately afterward. All original calls,
conditions, damage arithmetic, and RNG ordering are preserved. VC6 combines the
bullet predicates and places the ion modifier after the shock-effect loop exactly
as native, without an explicit layout label or duplicated effect code.

`perk-and-heading-phase-mutations.json` records four complete controls. Separating
the heading phase, with either a combined or independent ion guard, reaches
100%: 237/237 instructions, 83/0/0 references, and the full 963-byte extent.
Splitting before Doctor or leaving Ion attached to heading is byte-neutral at
89.87%. This supersedes the earlier closed compiler-provenance conclusion.
