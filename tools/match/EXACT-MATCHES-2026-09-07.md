# Eight exact recoveries and two instruction-count improvements

The matching checkpoint advances from **773/810 to 781/810 normalized exact functions**.
All eight new matches also have relocation-aware encoded-body identity, bringing that separate
count from **770/810 to 778/810**. Statistics formatting and bonus pickup publication improve
without becoming exact. Each of these ten source changes has its own commit.

The comparison baseline is `d9ea6e53f788c9fe735b17db10ec61697c3cf1e0`. Only the ten functions
below change their matching metrics; all target extents are preserved. Scope, reference maps,
shared headers, compiler settings, and translation-unit membership are unchanged.

## Exact recoveries

Each result is 100% with equal candidate/native instruction counts, a full exact prefix,
zero unresolved or mismatched references, and `body_byte_exact=True`.

| Function / evidence | Before | Instructions | Resolved references | Commit |
|---|---:|---:|---:|---|
| [player_fire_weapon](scratches/player_fire_weapon/NOTES.md) | 99.2063% | 378/378 | 142 | `27a4a5f35` |
| [ui_element_render](scratches/ui_element_render/NOTES.md) | 97.8887% | 521/521 | 65 | `8abf3b4c0` |
| [perk_apply](scratches/perk_apply/NOTES.md) | 99.5851% | 241/241 | 76 | `4cf163f92` |
| [demo_trial_overlay_render](scratches/demo_trial_overlay_render/NOTES.md) | 98.1132% | 636/636 | 175 | `d6445ad99` |
| [creature_spawn](scratches/creature_spawn/NOTES.md) | 88.6076% | 79/79 | 35 | `c99bb791d` |
| [quest_select_menu_update](scratches/quest_select_menu_update/NOTES.md) | 95.8904% | 803/803 | 284 | `75350a669` |
| [unlocked_perks_database_update](scratches/unlocked_perks_database_update/NOTES.md) | 99.8043% | 511/511 | 148 | `a02193c85` |
| [unlocked_weapons_database_update](scratches/unlocked_weapons_database_update/NOTES.md) | 99.8088% | 523/523 | 157 | `681d84900` |

Player firing separates the two sprite-position lifetimes from the loop-local pellet position.
UI element rendering uses the authenticated SDK vector expressions and union-backed array view.
The trial overlay combines SDK button expressions with next-line Y publication. The quest menu
needs the interaction of panel ownership, independent row advancement, branch-local indexing,
borrowed checkbox X, and Back-button construction; isolated changes do not recover the match.

Perk application retains the cached player count in callback-bearing Ammo Maniac and Bandage
loops while pure loops read the configured count. Creature spawning separates initialization
from final publication through two inline helpers and corrects the health multiplier to the
native binary32 value. The two database screens recover their separator schedule through an
inline helper that receives position by value and the measured integer width by const reference.
The per-function notes and committed mutation plans retain the ablation evidence.

## Further improvements

| Function / evidence | Before → after | Instructions, before → after | References, before → after | Commit |
|---|---:|---:|---:|---|
| [statistics_menu_update](scratches/statistics_menu_update/NOTES.md) | 93.2642% → 94.5266% | 675/676 → 676/676 | 276/0/0 → 276/0/0 | `3246e6c94` |
| [bonus_render](scratches/bonus_render/NOTES.md) | 92.0460% → 92.6471% | 1087/1088 → 1088/1088 | 229/0/0 → 232/0/0 | `0fcab4e8b` |

References are resolved/unresolved/mismatched. Both functions retain their exact prefixes
(280 and 14 instructions respectively) and remain WIP with `body_byte_exact=False`.

Statistics formatting combines session renderer capture with reuse of minute/second locals for
their displayed remainders. It preserves the native time-formatting quirk and recovers the
missing arithmetic instruction. Direct indexed telekinetic pickup publication recovers the
missing bonus instruction and three aligned references; the indexed search also restores the
native signed loop bound. Higher-scoring alternatives that lose an instruction remain rejected
controls rather than retained source.

## Verification and remaining work

The full native audit and checkpoint pass:

```sh
uv run crimson native audit --image crimsonland.exe --require-game-closure -j 8
uv run crimson match checkpoint --base d9ea6e53f788c9fe735b17db10ec61697c3cf1e0 -j 8
```

The checkpoint reports zero scope, claim, evaluation, metadata, experiment, strict-experiment,
and native errors. Its baseline comparison finds the ten intended improvements and no regressions.
The EXE audit reproduces 671 functions in 663 objects, passes ABI assertions and both function
and game-owned closure, and reports zero hard duplicates. Its 97 remaining external references
are unchanged: 71 excluded functions, 25 imports, and one toolchain symbol. Both images' native
artifacts are current; Grim remains 139/139 exact.

| Checkpoint measure | Before | After |
|---|---:|---:|
| EXE normalized exact functions | 634/671 | 642/671 |
| All-image normalized exact functions | 773/810 | 781/810 |
| All-image encoded-body exact functions | 770/810 | 778/810 |
| Extent bytes in normalized-exact functions | 189,131/341,992 | 203,669/341,992 |
| Fuzzy-weighted bytes, rounded | 312,005/341,992 | 312,353/341,992 |
| Remaining functions / extent bytes | 37 / 152,861 | 29 / 138,323 |
| Reproducible candidates | 810/810 | 810/810 |

Bounded unsuccessful controls are also recorded for eight remaining functions: random bonus
selection, creature death, Mods, Play Game, Spiders Inc., quest spawn scheduling, audio playback,
and survival. The invalid Play Game SDK plan generation is explicitly audited alongside its
corrected constrained replay; it is not counted as a valid source experiment. Current evidence
labels and the remaining 29-function map are in [STATUS.md](STATUS.md) and [BATCHES.md](BATCHES.md).

The creature health literal exposes a separate port-parity follow-up. Native uses `0x38d1b718`,
while the Python and Zig ports still spell the multiplier as `1e-4` (`0x38d1b717`). The
[creature spawn notes](scratches/creature_spawn/NOTES.md) record the native data address and a
concrete rounding difference. This batch changes the recovered matching source only.
