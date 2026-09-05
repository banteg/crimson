# `projectile_spawn`

The current MSVC 6.5 `/O2 /GB` candidate recovers the full projectile
allocation and initialization semantics at `0x00420440`. It produces 114
instructions against 126 native instructions, scores 71.67%, and resolves all
13 candidate references without a mismatch.

Keeping the scan counter separate from the selected result is supported by the
native control flow: the bounded cursor loop tests the current slot, advances
by one `0x40`-byte projectile, branches back while the cursor remains below the
96-slot pool end, and selects slot `0x5f` only after exhaustion. The free-slot
path copies the counter into the return register. That source shape reproduces
the native nine-instruction allocator core and improves the candidate from
69.39%; the earlier first-slot special case scored 67.21%.

## Port-lineage evidence

The symbol-bearing Linux GOG 1.35 executable (SHA-256
`d261d92717ccf500d3652a72cd3f0164619e544c7d35c0cd49b8ba06caca5990`, ELF
build ID `0047a1e29c72da08d4432f434fe1c7c90da693d7b`) contains
`_Z11ShootBullet6vec2_tfii` / `ShootBullet` at `0x00571280` and a global named
`bullets`. Its 517-byte body preserves the same recognizable sequence: find a
free bullet slot with a saturated final slot, initialize position/origin/type,
derive velocity with sine and cosine, then select hit radius and damage by
projectile type. The newer port uses a 256-entry, `0x44`-byte pool and changed
type rules, so it is naming and source-lineage evidence rather than a byte-match
oracle. It strongly suggests `ShootBullet` as the historical source-level name
for this family.

The same symbol also recovers the first parameter as a two-component vector,
not an unstructured `float *`. The Windows body independently confirms that
shape by reading exactly the two adjacent floats and copying them to both the
projectile position and origin. The shared declaration, source, recovered
callers, and live Binary Ninja prototype therefore use `const vec2f_t *`; this
is ABI-neutral and leaves all six affected caller/callee match scores
unchanged.

The canonical 0x40-byte projectile record now has a separate flat Binary Ninja
view (`pos_x`/`pos_y`, origin, velocity, `type_id`, timers, damage, radius,
budget, and owner) while the matching view retains its evidenced
interior-cursor overlays. This is a type-presentation change only: exact
neighbors and the three large projectile candidates compile byte-for-byte as
before. Refreshing the authoritative type removes the former `pos.tail.vy.*`
decompiler paths without discarding the cursor evidence from matching source.

The initializer now copies the input through the matching record's canonical
`position` and nested `origin` aggregates. Both assignments compile identically
to the four scalar stores, preserving the 71.67% score and all 13 references.

Direct initializer fields now use the canonical flat `projectile_t::fields`
view as well. The nested `pos.tail.vy` view remains available for the update
loops whose native cursors genuinely begin at interior position or velocity
members, but it is not source shape for a record indexed from its base here.
The semantic `owner_id`, travel budget, type, timers, velocity, damage, and
radius names compile byte-for-byte identically at 114/126 instructions,
71.67%, and 13/0/0 references.

The flat owning-record view now carries explicit `origin` and `velocity`
aggregates. Initialization consequently copies `fields.origin` and writes
`fields.velocity.x/y`, while the nested cursor overlays remain reserved for
the update loops that actually begin inside the record. This is byte-neutral
at the same 114/126 instructions, 71.67%, and 13/0/0 references.

The recovered legacy `oldtypes.h` independently spells the source lineage as
`ShootBullet(vec2_t from, ...)`. A direct by-value reconstruction with the
available vector class changes VC6 alias analysis and regresses this target to
66.67%, so the scratch keeps the evidence-backed lowered pointer boundary
rather than pretending the available class definition reproduces the original
compiler semantics.

## Remaining compiler delta

The native function allocates one four-byte stack local, stores `1.0f` into it
before the Fire Bullets guard, repeats that store on the type-override backedge,
and reloads it for the default damage cases. Clean C and C++ forms with a local
`float`, an assignment in the override loop, common-tail damage selection,
nested switches, structured and label-based pool scans, `/O1`, MSVC 6.5pp, and
MSVC 7.0 either preserve or worsen the residual. The calibrated compiler keeps
the value as a constant or an x87 temporary instead. No address-taking,
`volatile`, aliasing trick, or dummy operation is retained merely to force the
native stack slot.

## Port parity

The native Fire Bullets override is global rather than owner-scoped: for legacy
owners `-100` and `-1..-3`, a non-Fire-Bullets projectile tests the first two
player timer slots, changes only the projectile type, and traverses the counter
loop twice. Both ports reproduce that exact owner window, global check, and
double shot credit when `preserve_bugs` is enabled. Corrected mode remains
owner-scoped and supports every generalized player slot. This does not alter
the scratch candidate or its score.

## Recovery classification audit

Live Binary Ninja confirms the native four-byte local is initialized to
`1.0f` at `0x00420451`, written again on the Fire Bullets override backedge at
`0x004204a6`, and read only by the default-damage cases. The ordinary local in
the candidate expresses that value, but calibrated VC6 folds it to constants;
the missing 12 instructions and later offsets follow from that one backend
choice. The allocation loop, override loop, field initialization, type
branches, returns, and all 13 references are otherwise accounted for.

Classification is `RECOVERY=semantic-complete`, `RESIDUAL=compiler`. The
metadata-only change preserves the before/after result: 71.67%, prefix 0/126,
114 candidate versus 126 target instructions, and references 13/0/0.

## Recorded default-damage backedge search

`default-damage-backedge-mutations.json` records five declaration and
Fire-Bullets backedge combinations. Separating declaration from assignment is
byte-neutral. Repeating the evidenced `1.0f` assignment on either side of the
type override raises the candidate to 120 instructions but worsens the score
to 69.92%; the backend still does not reproduce native's four-byte local, so
the redundant source assignment is not retained.

## Recorded vector value-ABI search

The recovered `oldtypes.h` by-value declaration motivated a bounded ABI check
rather than another control-flow rewrite. `vector-value-abi-mutations.json`
temporarily masks the lowered pointer prototype from the shared matching
header, then tests an eight-byte vector value with a default constructor,
scalar constructor, copy constructor, destructor, or copy constructor plus
destructor. This isolates the VC6 non-POD parameter-lowering hypothesis while
leaving the function body unchanged.

All five variants compile, preserve `13/0/0` references, and produce the same
69.20% result, a regression from the 71.67% lowered-pointer baseline. The spec
SHA-256 is
`61105c369e7877c31940a539980077ae50c1d1d537eb2ff87ee9182e5e24853d`.
Special-member-driven by-value lowering therefore does not recover the native
four-byte default-damage local, and the canonical scratch retains the
evidence-backed pointer boundary.

## Recorded vector reference-ABI search

The remaining plausible legacy C++ boundary is a vector reference rather than
a value or lowered pointer. `vector-reference-abi-mutations.json` masks the
shared pointer prototype and tests both `const vec2f_t &` and mutable
`vec2f_t &`, aliasing the reference back to the existing pointer-owned body so
only parameter lowering and alias analysis change.

Both planned variants are byte-identical to the 71.67% baseline at 114/126
instructions with `13/0/0` references. A reference ABI therefore does not
materialize the native default-damage stack slot or its override-backedge
store. The pointer boundary remains canonical. The spec SHA-256 is
`a639266f2e0d27ac080c5eeb3fafbb669e42016b070464dc54863e3cacf5d533`.

## MOD SDK pool-sentinel transfer

The authenticated `rSpawnProj`, `rSpawnRock`, and `rSpawnPart` source/DLL
pairs use a pointer plus a last-entry sentinel. That is a useful house-style
hypothesis, but the game target and its exact `creature_alloc_slot`,
`creature_spawn_slot_alloc`, and `bonus_alloc_slot` neighbors instead support
the current one-past pool bound.

`sdk-pool-sentinel-mutations.json` records complete 5/5 coverage of the SDK
last-entry loop, its break form, the exact-game `for` spelling, and declaration
interactions. The one-past `for` loop and unused last-entry declaration are
byte-identical to the 71.67%, 114/126-instruction, `13/0/0` baseline. The SDK
`while (projectile != end)` form keeps the same normalized score and instruction
count only because the bound operand is masked, but the reference audit falls
to `12/0/1`: it names `projectile_pool[0x5f]` where native names the one-past
`projectile_pool[0x60]`. Replacing the shared initialize edge with an SDK-style
break falls to 65.82%, 111 instructions, and `11/0/0` references.

Mutation reporting now treats that byte-neutral `12/0/1` result as an explicit
reference tradeoff; relocation masking can no longer make this shape appear
warning-free merely because its normalized score ties the baseline.

No source change is retained. This establishes the MOD SDK as a bounded
source-style prior rather than authority over 1.9.93 semantics. The spec
SHA-256 is
`08d6958a585819a0840c1f4ac02863acacc8982ff047bcd86d2d48ec4686ed5e`.

## Focused follow-up (2026-09-05)

Nine shared local-damage tail forms cross chained conditions, independent
conditions, and a switch with the existing override loop, a damage reset, or
tail recursion. None improves 71.67%; the best reaches only 67.21%. These
ordinary shared-sink forms do not recover the native default-damage stack
lifetime.

The complete bounded matrix is recorded in
`shared-damage-consumer-followup-mutations.json`. No source change is
retained; this result bounds these specific hypotheses only.
