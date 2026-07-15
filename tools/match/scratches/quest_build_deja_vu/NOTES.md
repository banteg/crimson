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
cosine, live sine, rounded x product, and copied final position words. The VC6
candidate scores 83.20% with 62 instructions against 63. Its remaining gap is
the optimizer's induction base (`entry` versus `entry.trigger_time_ms`) and
the placement of independent template, trigger, and count stores. No aliasing
or artificial dependency is added to force those choices.
