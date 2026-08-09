# `quest_build_nesting_grounds`

Native target: `crimsonland.exe` at `0x004364a0` (626 bytes).

Live Binary Ninja evidence recovers twelve fixed quest entries. Entries 0, 4,
5, 10, and 11 repeatedly recompute the same dynamic position from signed
integer `terrain_texture_width / 2` and `terrain_texture_height + 64`; the
remaining entries form a fixed nest pattern around the map. Heading is left
untouched. The entries are:

- template `0x1d`, trigger 1500, count `player_count * 2 + 6`;
- template `0x09` at (256, 256), trigger 8000, count 1;
- template `0x09` at (512, 512), trigger 13000, count 1;
- template `0x09` at (768, 768), trigger 18000, count 1;
- template `0x1d`, trigger 25000, count `player_count * 2 + 6`;
- template `0x1d`, trigger 39000, count `player_count * 3 + 3`;
- template `0x09` at (384, 512), trigger 41100, count 1;
- template `0x09` at (640, 512), trigger 42100, count 1;
- template `0x09` at (512, 640), trigger 43100, count 1;
- template `0x08` at (512, 512), trigger 44100, count 1;
- template `0x1e`, trigger 50000, count `player_count * 2 + 5`;
- template `0x1f`, trigger 55000, count `player_count * 2 + 2`.

The recovered two-field spawn metadata setter is the same source idiom that
matches `quest_build_two_fronts` and `quest_build_zombie_masters` exactly.
Using it across the table first raised the honest match from 94.93% to 97.10%.
A recorded lifetime sweep then found that naming the position pointer for entry
six preserves the source's typed aggregate boundary and delays its fixed stores
to the native schedule. That minimal retained form raises the match again to
98.55% while preserving the exact 138-instruction body and all fifteen audited
references. In particular, it eliminates both late metadata interleavings from
the x87 position conversions rather than constraining those stores artificially.
The typed pointer removes the third scheduling cluster without a barrier,
volatile access, or artificial dependency.

A second recorded boundary sweep found that naming only the entry-two count
pointer preserves another natural typed member lifetime. That retained form
raised the match to **99.28%**, still with the exact 138-instruction body and
all fifteen audited references. It eliminated the shared `768.0f` scheduling
cluster without changing any value or store.

A focused follow-up using the exact fixed-table house style recovered the final
interaction. A plain append counter is byte-identical by itself. Publishing
entry one's template and trigger through direct fields without the counter
regresses to 96.38%. Together, the append counter and that one direct metadata
boundary move the shared template-9 load before the `edi` save, exactly as in
native. The candidate now matches all **138 instructions** and **626 bytes**,
with all fifteen audited references resolved.
Attempts to model the positions as vector temporaries introduce 42 extra
instructions; fixed-position setters retain the same score while regressing
other scheduling. The direct position fields, append counter, and entry-specific
metadata boundary are therefore the strongest plausible source shape without
artificial dependencies or register forcing.

## Recorded mutation evidence

`scheduling-boundary-mutations.json` evaluates every one- and two-site
combination across five entry-three and five entry-six lifetime forms: 35
variants total. The minimal `quest_vec2_t *` for entry six improves the fuzzy
weight by 9.07 bytes and is retained; the entry-three pointer alone helped the
old baseline by 4.54 bytes but was subsumed by the stronger entry-six shape.
The plan SHA-256 is
`110552e57c2a5a750689f33613709f511e99e6d094633616fbd9bca7e2922621`.

Two follow-up matrices use the improved 98.55% baseline.
`entry-three-refinement-mutations.json` records eight pointer, scalar,
chained-assignment, and member-order forms; all are neutral or worse.
`prologue-register-lifetime-mutations.json` records six shared-template,
singleton-count, and first-position lifetime forms; all are byte-neutral.
Their SHA-256 values are
`b519e29a17081168087280e0a116d6b70ce6b0a9e2bc09da16f6a9e015480fc4`
and
`2002ffa7ab7dd3cb07d707c36f9269d23a4c46476bd76cc87929ab580e2bfb9f`.

`entry-two-metadata-boundary-mutations.json` evaluates eight typed record,
position, count, cursor, and direct-field forms. The minimal `int *` count
pointer adds **4.54 fuzzy-weighted bytes** and is retained. Its SHA-256 is
`5d1aef7879c46fd3bca2fd823146570673281fc357ef37732803546392f512d5`.

`first-fixed-entry-order-mutations.json` then evaluates eight natural
statement-order and member-lifetime forms against the 99.28% result; every
variant regresses. Six shared-constant declaration-order shadow probes are
also byte-neutral, with a representative result recorded in
`experiments.jsonl`. MSVC 6.5 and 6.6 tie, the processor-pack compiler
regresses, and the `/G5`, `/G7`, `/Ox`, and `/Ob1` flag probes are neutral.
The final order matrix SHA-256 is
`3a4622c8060f2ab40ab5c2960a0ef4733a742aa4b016c9a77a11951c98dc785f`.

`metadata-helper-shape-mutations.json` adds five explicit-inline,
force-inline, explicit-`this`, reverse-store, and reference-return spellings.
Four are byte-neutral and reversing the helper stores regresses by 54.4
fuzzy-weighted bytes. Its SHA-256 is
`fb81a462be22f2b5c4f1f8b1aa4035c528732b595bd536db0a304ab38c97f3c4`.
A fresh compiler/flag matrix confirms MSVC 6.0/6.5/6.6 tie, Processor Pack and
MSVC 7.0 regress, and only `/G6` regresses among the tested VC6 flag variants.

`first-dynamic-position-lifetime-mutations.json` evaluates four typed and
scalar lifetimes around the first dynamic position. The typed record and
position pointers are byte-neutral; float locals lose 63.51 weighted bytes and
integer locals lose 127.01. At that checkpoint the `mov ebx, 9`/`push edi`
scheduling swap remained an honest compiler residual. The spec SHA-256 is
`0b0ae8da91b8097b4c179f6ca3770aa568e00ef4d9aeff1b9758b6e84651ca18`.

## 2026-08-09 append-publication completion

The exact recent fixed-table builders showed that append ownership can interact
with otherwise byte-neutral publication choices. Replacing fixed indices with
a single `entry_count` append counter is byte-identical at 99.28%. Changing only
entry one from `set_spawn()` to direct `template_id` and `trigger_time_ms`
publication regresses to 96.38%. Combining those two natural source choices
matches the native prologue schedule and the complete function exactly:
**100.00%**, **138/138 instructions**, **626/626 bytes**, and references
`15/0/0`.
