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
