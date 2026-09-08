# Reference and translation-unit audit (2026-09-08)

Baseline: `0d00a81ea` plus the pre-existing Spiders Inc. evidence-only changes.
The reference image is Crimsonland 1.9.93 GOG. Source/configuration changes to
Spiders Inc. are outside this slice; its prior uncommitted evidence is preserved.

The live full-corpus comparison starts and ends at **793/810 normalized exact**,
**791/810 relocation-aware encoded-body exact**, and **810/810 evaluated**.
No recovered gameplay source, compiler profile, reference alias, or symbol map
changes. Only Controls' reference counts change: **1559/0/9 -> 1564/0/4**.
Its **5413/5421 instructions**, **172-instruction prefix**, **81.7242016%**
alignment, and non-exact encoded body are unchanged.

## Five false reference mismatches came from table overreads

Native guards at `0x0044aa9e`, `0x0044b807`, and `0x0044c572` compare EAX
against `0xec`, branch above to default, clear the dispatch register, load a
byte case index, then jump through a dword table. This proves **237** lookup
entries for each dispatch. The three maps start at `0x0044e574`,
`0x0044e8a8`, and `0x0044ebdc`.

The previous content-scanning heuristic used **240 candidate bytes** and
**241 native bytes**. It swallowed three zero padding bytes on both sides,
then native bytes `21`, `8d`, or `1d` from the following jump table. Those
bytes are smaller than the number of switch destinations, so scanning until
an invalid case index could not identify the boundary.

The matcher now recognizes an adjacent unsigned guard, byte load, and indirect
jump using the same checked index. A byte-register load must have its upper
bits cleared; a zero-extending load may supply a full register directly.
Wrong registers, a signed guard, a clobbered index, a default edge entering the
dispatch, or another direct branch/call into the guarded sequence invalidate
the bound. Shared tables must have consistent guarded consumers; an unguarded
consumer invalidates the inferred extent for the pair. COFF relocations must
identify the paired adjacent tables. The
existing sparse-partition comparison then consumes exactly the proven domain;
changed or invalid live case entries still fail. Unrecognized forms retain the
previous behavior. No alias or fuzzy-score exception is introduced.

This corrects five of the seven original compiler-table mismatches. The
Controls analog table and creature-template retry table retain their real
function-relative destination differences. The table fix changes no emitted
object bytes and earns no additional exact function.

## All 46 original mismatches

Addresses and candidate offsets below identify the pre-fix audit entries.
`operation pairing` describes an instruction-alignment mismatch, not permission
to equate the named operands. `induction anchor` requires compensating field
accesses and the same loop extent. All 41 remaining mismatches stay visible;
none of these classifications changes acceptance or proves global semantic
correctness. The eight functions' existing NOTES and fresh target/candidate
assembly were inspected, including live Binary Ninja disassembly.

| Function | Native instruction | Candidate offset | Classification | Evidence |
|---|---|---|---|---|
| `controls_menu_update` | `0x00449268` | `+0x598` | induction anchor | Runtime binding destination advances by 0x360; the candidate starts four bytes later and compensates in field displacements. |
| `controls_menu_update` | `0x004492a1` | `+0x5d1` | induction anchor | Persisted binding cursor uses the axis-X interior anchor; candidate uses config+0x1cc with compensating loads and the same 0x40 stride. |
| `controls_menu_update` | `0x00449401` | `+0x743` | operation pairing | The neighboring outline X/Y additions use 54 and 13 in opposite instruction order; both constants remain present. |
| `controls_menu_update` | `0x0044aaab` | `+0x1de2` | tooling overread | 237 live lookup indices agree; the old PE key included an extra byte from the next jump table. |
| `controls_menu_update` | `0x0044aab1` | `+0x1de8` | tooling overread | Same bounded partition as the preceding lookup; the actual jump destinations remain displaced by +7. |
| `controls_menu_update` | `0x0044b814` | `+0x2b46` | tooling overread | 237 live lookup indices agree; the old PE key included an extra byte from the next jump table. |
| `controls_menu_update` | `0x0044b81a` | `+0x2b4c` | tooling overread | Same bounded partition as the preceding lookup; the actual jump destinations remain displaced by +2. |
| `controls_menu_update` | `0x0044c57f` | `+0x38af` | tooling overread | 237 live lookup indices agree; the old PE key included an extra byte from the following analog dispatch table. |
| `controls_menu_update` | `0x0044dc16` | `+0x4f1a` | local code layout | Six compiler-local destinations are each -0x2c in the candidate; retain the mismatch. |
| `creature_render_type` | `0x00418eb0` | `+0x34a` | induction anchor | Native max-health cursor versus candidate max-health+0x44; active/type/health accesses compensate by -0x44. |
| `creature_render_type` | `0x00419171` | `+0x60e` | induction anchor | Native animation cursor versus candidate type-id cursor in the same 0x98-byte creature records. |
| `creature_render_type` | `0x004193d1` | `+0x84c` | induction anchor | The matching end cursor shifts with the animation/type-id base; same 384-record traversal. |
| `creature_render_type` | `0x0041945e` | `+0x8d9` | induction anchor | Native lifecycle cursor versus candidate hit-flash cursor; field displacements preserve the same records. |
| `creature_render_type` | `0x00419638` | `+0xaac` | induction anchor | The matching end cursor shifts with the lifecycle/hit-flash base; same 384-record traversal. |
| `creature_spawn_template` | `0x004340c3` | `+0x35e4` | local code layout | All four retry destinations are +0x11 in the candidate, following preceding code-size differences. |
| `creature_update_all` | `0x004272fa` | `+0x1047` | operation pairing | Native Toxic Avenger load is paired with the later Veins of Poison load; both perk checks are present. |
| `creature_update_all` | `0x0042731e` | `+0x1070` | operation pairing | Native second perk_count_get is paired with the later player_take_damage call; both callees occur in each contact path. |
| `highscore_screen_update` | `0x00442feb` | `+0xbdd` | operation pairing | Three successive sfx_mute_all calls load theme, Shortie Monk, and extra IDs; repeated call sequences pair different members. |
| `highscore_screen_update` | `0x00442ff6` | `+0xbe8` | operation pairing | Same three-call mute sequence; native extra ID is paired with candidate Shortie Monk ID. |
| `highscore_screen_update` | `0x0044324e` | `+0xe04` | operation pairing | Native +364 coordinate addition is paired with candidate +32; candidate +364 occurs six instructions later. |
| `highscore_screen_update` | `0x00443638` | `+0x11fd` | operation pairing | Native list.items (+0x0c) publication is paired with list.selected_index (+8); count and selection stores are reordered. |
| `player_update` | `0x00413eb2` | `+0x7d3` | induction anchor | Candidate creature-pool cursor starts at position.y (+0x18); active/health reads compensate, preserving the same traversal. |
| `player_update` | `0x0041419e` | `+0xabe` | operation pairing | Native overlay-player load at the preceding arm tail is paired with the next weapon arm interface load. |
| `projectile_render` | `0x004237e4` | `+0xa1e` | induction anchor | Native projectile position.y (+0x0c) versus candidate timer (+0x2c), with compensating active/type loads. |
| `projectile_render` | `0x00424114` | `+0x137d` | induction anchor | The 96-projectile end cursor shifts by the same +0x20; the native endpoint happens to have a particle-field name. |
| `projectile_render` | `0x004247fe` | `+0x1bbd` | operation pairing | Native ion-arm alpha scale 2.5 is paired with a later candidate size scale 3.1; inspect the complete arm before editing literals. |
| `projectile_render` | `0x00424808` | `+0x1bc7` | operation pairing | Native alpha cap 1 is paired with the later candidate size cap 9, following the previous cross-operation pairing. |
| `projectile_render` | `0x004253bb` | `+0x2511` | induction anchor | Fire-overlay cursor starts at projectile root versus candidate +4, with compensating active and position accesses. |
| `projectile_render` | `0x004253eb` | `+0x253c` | operation pairing | Native camera X load is paired with candidate camera Y; both components feed the same quad draw. |
| `projectile_render` | `0x00425444` | `+0x257d` | induction anchor | Fire-overlay end cursor differs by the same +4 across 96 records; native endpoint is named particle_pool. |
| `projectile_render` | `0x00425561` | `+0x26bd` | operation pairing | Native first secondary-sprite centering subtracts 3; alignment pairs the next candidate 8-pixel sprite subtracting 4. |
| `projectile_render` | `0x004255b2` | `+0x26f6` | operation pairing | Native 8-pixel sprite X centering (-4) is paired with the later 4-pixel sprite Y centering (-2). |
| `projectile_render` | `0x004255cd` | `+0x2708` | operation pairing | Native 8-pixel sprite Y centering (-4) is paired with the later 4-pixel sprite X centering (-2). |
| `projectile_update` | `0x004212c1` | `+0x73b` | operation pairing | Shock-chain delta X load is paired with delta Y; native uses fxch before fpatan and candidate reverses the load order. |
| `projectile_update` | `0x004212ce` | `+0x748` | operation pairing | Shock-chain delta Y load is paired with delta X, complementing the preceding reversed load. |
| `projectile_update` | `0x004212d5` | `+0x74f` | address materialization | Native materializes the next creature position; candidate materializes its containing record. The projectile origin remains the separately preserved position input. |
| `projectile_update` | `0x00421ab1` | `+0xee1` | induction anchor | Creature position.y cursor versus candidate position.x; active and coordinate displacements compensate. |
| `projectile_update` | `0x00421b9d` | `+0xfc8` | induction anchor | The corresponding 384-creature end cursor shifts by the same -4. |
| `projectile_update` | `0x004221ba` | `+0x15cc` | operation pairing | First decal vector publishes X/Y in a different order; native X addition pairs with candidate Y. |
| `projectile_update` | `0x004222a3` | `+0x16b0` | operation pairing | Second decal vector has the same reversed component publication. |
| `projectile_update` | `0x0042238e` | `+0x178f` | operation pairing | Third decal vector has the same reversed component publication. |
| `projectile_update` | `0x004224f0` | `+0x18db` | induction anchor | Native particle velocity.y (+0x10) versus candidate age (+0x2c), with compensating active/type accesses. |
| `projectile_update` | `0x004225dd` | `+0x19b4` | operation pairing | Native particle damping factor 0.9 pairs with a different candidate frame-dt multiplication in the motion path. |
| `projectile_update` | `0x0042263b` | `+0x1a3b` | operation pairing | Native motion scale 2.5 pairs with frame_dt; the candidate multiplies by 2.5 in its following instruction. |
| `projectile_update` | `0x004226b9` | `+0x1a5a` | operation pairing | Native zero-lifetime comparison pairs with candidate 0.8; the zero and nonzero-type branch bodies are arranged differently. |
| `projectile_update` | `0x004226d3` | `+0x1a72` | operation pairing | Native 0.8 comparison pairs with candidate zero, complementing the preceding branch-order pairing. |

## Proven minimum translation-unit ownership

The weapons and perks database callbacks are independently exact now. Each
canonical callback object already emits its two local-static destructor
thunks. High-score screen likewise emits nine exact local-static thunks while
its callback remains WIP. Binding those native functions to their actual
COFF-local members removes **13 redundant standalone objects**, reducing the
EXE selection from **663 to 650 objects**, with **671 native functions** and
**six ownership clusters**. The source objects themselves are unchanged.

These are minimum co-resident groups, not recovered original filenames or
proof of the complete outer TU boundary. In particular, adjacency and shared
widget classes do not establish that the weapons and perks callbacks belonged
to one original TU. They stay separate. The older combined-neighbor probes
were negative at their then-current source; they are not positive provenance.

All 13 thunks are native one-byte `ret` bodies and compiler-generated static
symbols (`IMAGE_SYM_CLASS_STATIC=3`), not external replacements. Each is tied to
its native registration push by the callback's existing masked-reference audit:

| Owner | Registration push | Local symbol | Native thunk |
|---|---|---|---|
| `unlocked_weapons_database_update` | `0x440430` | `_$E2` | `unlocked_weapons_scrollbar_destroy` (`0x440950`) |
| `unlocked_weapons_database_update` | `0x440525` | `_$E3` | `unlocked_weapons_back_button_destroy` (`0x440940`) |
| `unlocked_perks_database_update` | `0x440c80` | `_$E2` | `unlocked_perks_scrollbar_destroy` (`0x441190`) |
| `unlocked_perks_database_update` | `0x440d72` | `_$E3` | `unlocked_perks_back_button_destroy` (`0x441180`) |
| `highscore_screen_update` | `0x442a9c` | `_$E2` | `highscore_hardcore_checkbox_destroy` (`0x4443b0`) |
| `highscore_screen_update` | `0x442c92` | `_$E3` | `highscore_score_scrollbar_destroy` (`0x4443a0`) |
| `highscore_screen_update` | `0x442d76` | `_$E4` | `highscore_update_button_destroy` (`0x444390`) |
| `highscore_screen_update` | `0x442ece` | `_$E5` | `highscore_play_button_destroy` (`0x444380`) |
| `highscore_screen_update` | `0x443046` | `_$E6` | `highscore_back_button_destroy` (`0x444370`) |
| `highscore_screen_update` | `0x4432cb` | `_$E7` | `highscore_online_scores_checkbox_destroy` (`0x444360`) |
| `highscore_screen_update` | `0x443387` | `_$E8` | `highscore_date_filter_list_destroy` (`0x444350`) |
| `highscore_screen_update` | `0x4435e1` | `_$E9` | `highscore_player_count_list_destroy` (`0x444340`) |
| `highscore_screen_update` | `0x44372e` | `_$E11` | `highscore_game_mode_list_destroy` (`0x444330`) |

Every cluster member is compared independently against its canonical native
extent. The two exact callbacks retain 523/523 and 511/511 instructions and
157/0/0 and 148/0/0 references; all 13 destructors retain encoded-body identity.
High-score retains its existing 1969/2004 instructions and 594/0/4 references.
The TU gate now also rejects loss of previously proven encoded-body identity,
even when normalized score and reference counts are unchanged.

## Next source-recovery work

The remaining references support whole-function allocation and value-lifetime
work, not blanket data-map repairs. Player update's weapon-arm boundary and
projectile rendering's conventional-trail/ion-arm locals are higher-value
regions than another broad Spiders Inc. count-publication sweep. Correlate
compiler listings, both coordinate components, callers and callee argument
ownership across the whole lifetime before choosing a bounded source probe.
Do not replace literals based on an aligned reference row alone.

For larger TU recovery, look for compiler-local call/registration edges and
shared storage ownership that require co-residence. Shared constants, adjacent
addresses, similar classes, and a better combined-object score are leads,
not sufficient provenance for merging callbacks.

## Reproduction

```sh
.venv/bin/pytest -q tests/test_match*.py tests/native/test_native_link.py
.venv/bin/crimson match audit --all-scores --json -j 8
.venv/bin/crimson native audit --image crimsonland.exe --require-game-closure -j 8
.venv/bin/crimson native audit --image grim.dll --require-game-closure -j 8
.venv/bin/crimson match checkpoint --base 0d00a81ea -j 8
.venv/bin/crimson native verify --require-game-closure
```

All **423** matching/native tests pass; Ruff and type checks pass for the
changed tooling. Both structural links were rebuilt against the final audit,
retain zero placeholders, and reproduce their saved output hashes. Their
`runnable=true` receipts describe provider completeness, not a gameplay test.

The full status comparison against the pre-fix snapshot changes only Controls'
five reference results. Scope, target extents, instruction counts, scores,
exact prefixes, and normalized/encoded exactness remain identical everywhere.
Checkpoint regression, scope, claim, evaluation, metadata, experiment,
strict-experiment, and native error counts are all zero. The matcher change
advances experiment epochs, so earlier source sweeps are now historical-only;
their evidence and source remain intact.

The eight inspected source digests pin the classification epoch:

| Source | SHA-256 |
|---|---|
| `tools/match/scratches/controls_menu_update/scratch.cpp` | `86c10a5d49356e52c062ba14d52e6c0db01690ab2e3b9a47ae7b24d017af2b7e` |
| `tools/match/scratches/creature_render_type/scratch.cpp` | `64c270c898ac14e21ab7ad932cc0cf83a5bdc7d97b397461b102ff93276f7086` |
| `tools/match/scratches/creature_spawn_template/scratch.cpp` | `5c1fdd779bb8b027eca91c28d9d113a7cbaf6b965a85a542f8b161b8d0c3305f` |
| `tools/match/scratches/creature_update_all/scratch.cpp` | `854a1dcf34a2b8e21695af7dfa23ade204da4172a3004ad4cd8adcd44636cb17` |
| `tools/match/scratches/highscore_screen_update/scratch.cpp` | `8666b3ecc039f3fe4a3d1078629152136f2cd3ada463a48c0f07a9512bed93be` |
| `tools/match/scratches/player_update/scratch.cpp` | `1a7e3490cde7dfc566818418d2dfd7a242fbb6eb0dab810aa4eab854aa94c7fe` |
| `tools/match/scratches/projectile_render/scratch.cpp` | `57d0adb7c5305072e2405207031de48041ef8a29a42786b6320a1c5f9acfa063` |
| `tools/match/scratches/projectile_update/scratch.cpp` | `7245eccc7426b22b561a90b4d4a024f3c6d769c274f24cc760b034043973edc1` |
