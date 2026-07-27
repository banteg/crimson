# `quest_build_deja_vu`

Native target: `crimsonland.exe` at `0x00437920` (209 bytes).

Live Binary Ninja evidence recovers 18 radial waves of four aliens each. The
trigger starts at 2000 ms. Its step also starts at 2000 ms, falls by 80 after
each wave, and continues while the next step is greater than 560. Each wave
uses `(crt_rand() % 612) * 0.01`, radii 84, 126, 168, and 210, center
`(512, 512)`, template `0x0d`, and count 1. The native writes the constant
final count 72.

The key source-shape recovery is the two-stage vector construction. A rounded
radial offset is constructed first and then translated by `(512, 512)`. This
reproduces the native 24-byte frame and its x87 sequence, including the saved
cosine, live sine, rounded x product, and copied final position words. The typed
trigger-field cursor recovered by the mutation sweep makes the native induction
base explicit without changing the record layout. It improves the VC6
candidate from 83.20% to 84.13%, restores the native 63/63 instruction count,
and advances the exact prefix from 1 to 7 instructions. Its remaining gap is
register allocation and the placement of independent template, trigger, and
count stores. No aliasing or artificial dependency is added to force those
choices.

## Recovery classification audit

The live Binary Ninja loop accounts for all 18 waves, random-angle reduction,
four radii, translated vector construction, trigger recurrence, metadata, and
the constant count 72. All four references resolve. The remaining 63/63 delta
is confined to independent-store/x87 scheduling, so recovery is
`semantic-complete` with a `compiler` residual.

## Recorded mutation evidence

`trigger-cursor-mutations.json` evaluated four record/field cursor forms. The
retained typed current-record cursor adds 1.94 weighted bytes and is the only
improving form. Thirteen declaration/lifetime combinations and four
entry-store boundary forms were then exhaustively checked; they were neutral,
failed to compile, or regressed. Their complete scores are recorded in
`experiments.jsonl`.
