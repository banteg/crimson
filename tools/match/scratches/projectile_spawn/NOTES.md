# `projectile_spawn`

The current MSVC 6.5 `/O2 /GB` candidate recovers the full projectile
allocation and initialization semantics at `0x00420440`. It produces 119
instructions against 126 native instructions, scores 69.39%, and resolves all
13 candidate references without a mismatch.

Keeping the scan counter separate from the selected result is supported by the
native control flow: the free-slot path copies the counter into the return
register, while the exhausted path selects slot `0x5f`. This source shape also
removes the prior first-slot special case and improves the candidate from
67.21%.

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
