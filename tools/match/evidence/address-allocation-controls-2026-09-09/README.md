# Bounded address-allocation controls

No control in this record produces a new exact function or improves a retained
candidate. Canonical source, compiler flags, headers, and ownership remain
unchanged. `results.json` identifies the source/configuration inputs and the
actual frontend/optimizer DLLs by SHA-256; its ratios are fractions, not
percentages. Every run uses `/O2 /GB /W3 /GR-` and the scratch's reference aliases.

## Distinct VC6 patch builds

Compile each of the five named canonical scratches with `msvc6.0`, `msvc6.3`,
`msvc6.4`, `msvc6.5`, and `msvc6.6`. These profiles contain distinct optimizer
binaries; equivalent matching results do not make them compiler aliases.

| Function | VC6 6.0 / 6.3 | VC6 6.4 / 6.5 / 6.6 |
| --- | ---: | ---: |
| statistics_update_check_worker | 89.945652% | 99.182561% |
| highscore_sync_worker | 93.155894% | 96.860133% |
| creature_handle_death | 89.486553% | 89.486553% |
| quest_spawn_timeline_update | 91.228070% | 91.228070% |
| quest_build_spiders_inc | 96.190476% | 96.190476% |

The recorded instruction counts, exact prefixes, and reference counts also
agree within each table cell. All reference audits are clean; all encoded-body
checks remain false. These results are controls on the current source forms,
not compiler-provenance attribution or a claim about other reconstructions.

## Network translation-unit order

Concatenate the entire statistics and high-score worker sources, preserving
their includes/declarations, in both orders. Compile each resulting single
translation unit with the canonical profile and match both function symbols.
All four results retain their standalone metrics. This tests those two orders
and those source files; it does not reconstruct or exclude their original full
translation unit.

## Creature record convenience unions

In a temporary include overlay, replace each anonymous scalar/component alias
union in `creature_t` with its existing named aggregate member: `position`,
`velocity`, `color`, `target_position`, and `target_offset`. Test each union
individually and then all five together. Preserve all other header contents and
compile the unchanged death scratch with a `sizeof(creature_t) == 152` check.

All six controls retain 205 candidate instructions against 204 native,
prefix 6, and 85 clean references at 89.486553%. Removing these presentation
aliases does not recover the native opening's two scaled address operands.
No header change is retained.
