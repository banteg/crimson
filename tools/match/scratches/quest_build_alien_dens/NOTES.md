# `quest_build_alien_dens`

Native target: `crimsonland.exe` at `0x00436720` (249 bytes).

Live Binary Ninja evidence recovers five template `0x08` alien dens. Two
corner dens spawn at `(256, 256)` and `(768, 768)` at 1500 ms; the center den
spawns at `(512, 512)` at 23500 ms with the player count; and the remaining
corners `(256, 768)` and `(768, 256)` spawn at 38500 ms. All other counts are
one, and the function returns five entries.

The native allocates one eight-byte position temporary and copies each pair of
float constants into the 24-byte records. A small `quest_vec2_t` constructor
plus direct metadata assignments preserves that source evidence, emits the
same 60 instructions, keeps template `8`, count `1`, and the active trigger in
the same registers, and resolves the player-count reference.

The residual is independent-store scheduling: VC6 groups several position and
metadata stores across adjacent records rather than retaining the native
per-entry order. Whole-entry setters, split metadata setters, folded builder
calls, `pos.set(x, y)`, explicit local-order variants, and reversed metadata
order were checked. They either remove the proven position temporary, swap the
long-lived trigger/count registers, or lower the score. The 68.33% candidate is
kept as an honest WIP without artificial dependencies.

## Recovery classification audit

The preceding BN recovery accounts for the complete control-flow, call (where
present), constant, record-store, and output-count policy. The candidate has
the same instruction count as native and all masked references resolved; its
localized residual is compiler scheduling/allocation only. Classification:
`RECOVERY=semantic-complete`, `RESIDUAL=compiler`.

## 2026-07-27 focused family pass

Live Binary Ninja reconfirmed the complete five-entry den table, including the
player-count center den. After the retained change, MSVC 6.0, 6.5, 6.5
Processor Pack, and 6.6 tie at 71.7948717948718%; 7.0 falls to
51.28205128205128%. `/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` tie, while
`/G6` reproduces the 7.0 regression and shortens the prefix.

`local-order-and-position-mutations.json` (SHA-256
`d309d8b32110c1c80672952f44092c9eb38330fe0bcb46e6a53eaad2c94af1d4`)
recorded ten variants. Direct scalar stores for only entry two's fixed center
position are the sole win; all five semantic local orders are neutral and the
other positions regress. After retaining that change,
`center-winner-interactions.json` (SHA-256
`ec5afa06e2c032874b4e2c025ff0da7538fdf42350a55eb12defa32d70d134b1`)
recorded nine follow-ups: local orders remain neutral and each additional
direct position regresses, so the center-only form is stable.

Validation improves 170.15/249 to 178.76923076923077/249 weighted bytes,
reducing the gap from 78.85 to 70.23076923076923 and raising the match from
68.33333333333333% to 71.7948717948718%. The result has 57/60 instructions,
prefix four, and references 1/0/0.
