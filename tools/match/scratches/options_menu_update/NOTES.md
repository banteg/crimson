# `options_menu_update`

Native target: `crimsonland.exe` at `0x004475d0` (1,621 bytes).

Current reconstruction: **76.29%**, 378 candidate instructions versus 377
native instructions, with 153 aligned references proven, no unresolved
references, and one alignment mismatch.

Live Binary Ninja and IDA evidence recovers the complete options-screen
callback. It positions the panel from UI element 31, renders the options
heading and labels, and owns local-static widgets for UI information text,
sound/music volume, graphics detail, mouse sensitivity, and Controls
navigation.

The callback translates the two volume sliders to 0.0..1.0 floats, clamps
graphics detail to presets 1..5 before applying it, and rounds/clamps mouse
sensitivity to 0.1..1.0. It also refreshes the violence-sensitive name and
description of the Bloody Mess / Quick Learner perk slot, routes the Controls
button, and handles Escape through the contextual Back action.

The remaining residual is global VC6 allocation/scheduling shape. The retained
panel ownership correction now gives the candidate the native `edi` save and
reuse for the detail maximum. The first region still orders independent x87
work and the four color-argument pushes differently, and the candidate has one
extra normalized instruction overall. The known VC6.5 point-profile, VC6.6,
VC6.5pp, VC7, and `/G6` checks did not reproduce that schedule; the
semantically direct `/GB` source remains the strongest result. The scratch is
consequently `semantic-complete` with a `compiler` residual. Its one visible
audit mismatch remains exposed rather than being treated as reference debt.

## Native-grounded SFX position sweep (2026-07-26)

Live Binary Ninja evidence localized the first slider-position divergence
without changing its recovered behavior. Native `0x004478b5..0x004478e0`
loads panel X, adds `148.0f`, stores that one x87 result first to `xy.x` and
then to the temporary slider X, and only then loads panel Y, adds `47.0f`, and
stores the temporary slider Y. The current object performs the same operations
in the same semantic order at function-relative `0x2e0..0x30b`; its different
stack slots follow the earlier frame/allocation divergence.

The recorded one-site sweep in
`sfx-slider-position-mutations.json` tested six ordinary C++ source shapes:
two declaration placements, both chained-assignment directions, a
slider-first copy, and a two-argument constructor. All six singles compiled to
the same matcher result as the baseline: **69.96%**, 372 candidate
instructions, prefix 8, `138/0/8` references, and exactly zero weighted-score
delta. There were no positive singles, so no interaction was eligible. The
complete sweep is recorded in `experiments.jsonl`; no source variant was
applied.

## Perk-slot refresh correction (2026-07-27)

A follow-up region pass selected the concentrated perk refresh and navigation
tail at `0x00447b6b..0x00447c12`. Live Binary Ninja shows the violence branch
loading the selected Bloody Mess / Quick Learner name and description pair at
`0x00447bc8..0x00447bf4` before writing the two fields of the same indexed perk
record. The prior source routed the description through a common temporary,
which made VC6 reverse the candidate register/reference pairing despite
identical runtime values.

The schema-1 `perk-slot-refresh-order` sweep tested all 5/5 planned natural
forms. Its spec SHA-256 is
`c408f4c669b8661f8fe69fabac788aa789b8bda6a94eeafb19ae79557aebda86`.
Keeping each selected name/description assignment together in its branch is
the only strong positive and is retained. It improves weighted bytes from
`1134.0507343124166/1621` (`69.95994659546061%`) to
`1154.152/1621` (`71.2%`), a gain of `20.101265687583464`; the gap falls from
`486.9492656875834` to `466.84799999999996`. Candidate instructions move from
372 to 373 against 377 native, prefix remains 8, and references improve from
`138/0/8` to `146/0/3`.

The retained source SHA-256 is
`65275e88c71a147c98eb7893d50eb49e3329d22b3afac1eeb619810c550addc5`.
Name-first ordering with a common description store gains only
`11.45593235425008` weighted bytes; the two one-branch reorderings are weaker,
and common name/description stores regress. The retained branch-local form is
ordinary behavior-equivalent C++ and contains no match-only construct.

## Panel ownership correction and mutation wave (2026-07-27)

Live Binary Ninja disassembly resolves the opening allocation cascade as a
source-ownership issue. After computing the adjusted working X, native
`0x0044763a..0x00447654` copies both working-vector components back into the
panel: Y is carried through `esi`, while adjusted X is stored, loaded into
`edi`, and published to the panel X slot. The heading quad at
`0x004476bc..0x004476c0` then passes panel Y in `esi` and panel X in `edi`.
The previous source copied only X and passed a mixed working/panel pair.

The complete 19-variant `panel-copyback-mutations.json` sweep found the
corresponding two-site interaction: whole-vector `panel_position = xy`
copyback plus panel-owned X/Y quad arguments. It improves weighted bytes by
`52.47316556291389`, from `1154.152/1621` to
`1206.625165562914/1621`; ratio rises from `71.2%` to
`74.43708609271523%`, prefix from 8 to 10, references from `146/0/3` to
`151/0/1`, and candidate instructions from 373 to 378. Its generated and
retained source SHA-256 was
`f4e5f016f2b1a9c713609984afad428ed727572a56e712b0523f8f62024f1c91`;
the spec SHA-256 is
`b0d263386d8db124df6bca4efb81a47c6ced3969711ad388aeaaf278fc1b80f6`.
The whole-vector copy alone and the mixed-coordinate alternatives regress,
which is why both source corrections are retained together.

With that ownership fixed, the complete 29-variant
`vector-assignment-schedule-mutations.json` sweep isolated one further
compiler-lifetime improvement. Returning a named, ordinary
`options_vec2_t result` from the inline addition helper gains
`17.176158940397272` weighted bytes without changing the instruction count,
prefix, or reference totals. It raises the final result to
`1223.8013245033112/1621` (`75.49668874172185%`) and lowers the gap to
`397.1986754966888`. The winning generated source SHA-256 was
`f04f3fe3f3b14b7a897ec8a978cf06352d7c9fdf15fd3c4f25bcc39fe8947ea5`;
the spec SHA-256 is
`edbe07e9ed1c0a46ca3530b94e177b8f371926fcb4fed6b0d01277be8ce86cf9`.
Explicit assignment operators all regress, so none was retained.

This wave evaluated 397 planned variants across eight complete recorded
sweeps, with no truncation:

- `opening-panel-lifetime-mutations.json`: 137 variants. Its only positive
  removes two candidate instructions and worsens references to `144/0/5`, so
  it was rejected.
- `detail-limit-lifetime-mutations.json`: 10 variants, all byte-identical.
  This proves native `edi = 5` follows the opening allocation rather than the
  detail declaration order.
- `heading-quad-coordinate-owner-mutations.json`: 3 variants. Panel-owned X/Y
  is the only positive and became part of the retained two-site correction.
- `panel-copy-semantics-mutations.json`: 68 variants. Explicit copy
  constructors and working-copy spellings add nothing; only the already-seen
  panel-owned quad arguments improve.
- `panel-copyback-mutations.json`: 19 variants, containing the retained
  `+52.47316556291389` interaction above.
- `vector-assignment-schedule-mutations.json`: 29 variants, containing the
  retained `+17.176158940397272` named-result lifetime above.
- `opening-vector-construction-v2-mutations.json`: 123 variants, all neutral
  or worse after the retained changes.
- `adjusted-panel-copyback-v2-mutations.json`: 8 variants, all worse.

The other spec SHA-256 values, in the same order, are
`6176405ee5ecc4d141edd312a986d30f996127618047d751a525800e606ca72b`,
`0f295ee67627efd4912be03150f952411cec34970523acd1cb879b9b4d6aafb4`,
`5551da65be28a5dc437b8d054606ec678d2d23f5e295056b53f5aea041072a76`,
`41e29c789f556a8ff80a2003ffca1dac8868a8c26615c53dac6479c17d1a5e4a`,
`c4ce2cf8814d7b2628c15c7732718525d182f14f8031e99534013e3d640b0225`,
and
`ac2eaec813733940e9d923ecf83839c6269b1bcbca40a7b0189429284606105f`.
All retained source is behavior-preserving C++; no volatile state, dummy use,
forced address, alias masking, inline assembly, or inert control flow is used.

## Direct perk-index publication (2026-08-09)

The highest remaining tail region at `0x00447b6b..0x00447bf4` combines the
Controls widget call with publication of the violence-sensitive Bloody Mess /
Quick Learner metadata. Native tests `config_blob.violence_disabled` before
loading `perk_id_bloody_mess_quick_learner`, then keeps that one indexed perk
record across both branch-local name/description stores. The previous source
first snapshotted the global ID into an ordinary local, which made VC6 schedule
the ID load before the violence byte.

Exact sibling `perks_init_database` uses the direct global-index spelling for
the same name/description pair. Transferring that ownership to this callback
makes the normalized perk-publication tail instruction-identical apart from
downstream label displacement. It adds `12.882119205298068` weighted bytes,
raising the result from `1223.8013245033112/1621`
(`75.49668874172185%`) to `1236.6834437086093/1621`
(`76.29139072847683%`). Candidate instructions remain 378 against 377 native,
prefix remains 10, and references improve from `151/0/1` to `153/0/1`.

A separate one-shot Controls coordinate object was also tested against the
native stack ownership. It allocated a fourth vector, shortened the prefix to
zero, and regressed the whole function to `74.43708609271523%`, so it was
rejected. The retained source contains only the direct, exact-sibling-backed
perk publication and leaves the existing widget coordinate lifetime intact.

## Current opening-allocation replay (2026-08-12)

Because the direct perk-index publication changes a tail lifetime in a function
whose remaining mismatch is global allocation, the earlier opening-vector
results were replayed rather than assumed to survive. The full current plan
covers 18 single-site variants, all 105 pairs, and all 200 three-site
interactions across the two-float constructor, opening panel expression, and
inline addition helper. A first 160-variant bounded run was superseded by the
complete 323/323 sweep with no truncation.

No current variant improves the retained source. The best constructor,
expression, helper, pair, and triple forms are byte-identical at
`1236.6834437086093/1621` (76.2914%), 378/377 instructions, prefix 10, and
references `153/0/1`; all remaining variants regress. The one aligned
reference mismatch therefore remains part of the opening stack/register
schedule, not an untested constructor interaction. No source change was
retained.
