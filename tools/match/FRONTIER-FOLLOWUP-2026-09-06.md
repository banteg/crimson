# Five-target matching follow-up — 2026-09-06

**Two WIPs improve; exact coverage remains 772/810.** The pass covers tutorial
formations, creature templates, mods storage, projectile simulation, and
projectile rendering. Eleven complete mutation plans evaluate all 85 controls;
one additional source probe confirms the final projectile helper formatting.

| Function | Before → after | Instructions C/N | References ok/?/! | Result |
|---|---|---|---|---|
| [tutorial_timeline_update](scratches/tutorial_timeline_update/NOTES.md) | 76.7560% → unchanged | 686/695 | 169/0/1 | 23 controls rejected |
| [creature_spawn_template](scratches/creature_spawn_template/NOTES.md) | 88.7658% → **88.8924%** | 3161/3159 | 357/0/1 | Late grid-child tint publication |
| [mods_menu_update](scratches/mods_menu_update/NOTES.md) | 98.9198% → unchanged | 648/648 | 184/0/0 | 8 controls neutral |
| [projectile_update](scratches/projectile_update/NOTES.md) | 62.6627% → **62.8819%** | 2176 → **2183/2203** | 417/0/18 → **426/0/13** | Field-backed tint clamp inputs |
| [projectile_render](scratches/projectile_render/NOTES.md) | 58.5506% → unchanged | 2885/3021 | 448/0/10 | 11 controls neutral |

The gains add **36.278402 fuzzy-weighted code bytes**. Remaining fuzzy gap is
29,995 rounded bytes, down from 30,031. Exact function extents still cover
188,401/341,992 bytes; fuzzy-weighted alignment is 311,997/341,992 bytes.
Relocation-aware encoded-body identity remains **769/810**, separate from
normalized exactness. All 810 candidates remain reproducible.

## Retained changes

- `b903654bb` moves the grid-child aggregate tint copy after stat publication.
  It improves the late alpha schedule without changing the loop induction,
  values, references, instruction count, or 0x48 frame. Fifteen controls show
  that adding induction changes reduces the gain.
- `6cb753d41` uses one inline tint clamp with a const-reference input for all
  four channels. It recovers field reloads, seven instructions, and five
  reference mismatches. Twenty-eight controls include stronger fuzzy scores
  that lose an instruction; those variants are not retained.

## Bounded findings and next work

Tutorial's complete branch-join and escaped-workspace forms all regress while
preserving the third alien spawn on both branches. The tutorial bonus table
and creature retry table retain their displaced local-jump-table reference
mismatches; no alias was added to hide them.

Native mods enumeration and version formatting share a stack area. Crossing
the two buffers' ordinary scopes does not recover that reuse: the candidate
frame remains 0x154 against native 0x144. A new ownership explanation is needed.

The renderer's named glow intermediates and inline sprite draw boundaries are
byte-neutral. The large conventional-trail and ion-arc regions remain separate
targets. Within batch 09, creature rendering has not received this focused pass.
None of these finite controls establishes that a function is unmatchable.

## Verification

- Current-source status evaluates all 810 candidates without errors. Comparing
  every function with starting commit `04ec81a68` finds only the two retained
  metric improvements; all target extents and existing exact matches agree.
- Native audit and verification require ABI, function closure, and game-owned
  closure for both images. Imports, excluded functions, and toolchain references
  remain outside full reference closure.
- The final matching checkpoint checks regression, scope, metadata, experiment,
  strict-experiment, and native artifact validity. No waivers are used.
- Every new mutation plan is complete and error-free. Commit hooks and
  whitespace checks pass; the remaining-function map and local links are checked.
