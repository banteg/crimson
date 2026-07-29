# `quest_build_alien_dens`

Native target: `crimsonland.exe` at `0x00436720` (249 bytes).

Live Binary Ninja evidence recovers five template `0x08` alien dens. Two
corner dens spawn at `(256, 256)` and `(768, 768)` at 1500 ms; the center den
spawns at `(512, 512)` at 23500 ms with the player count; and the remaining
corners `(256, 768)` and `(768, 256)` spawn at 38500 ms. All other counts are
one, and the function returns five entries.

The native reuses one eight-byte stack temporary while copying each pair of
float constants into the 24-byte records. The retained candidate models the
compiler-facing lifetime boundaries separately: entry one and the center use
typed position pointers, entry three uses a typed record pointer, and the last
entry uses the shared inlined metadata setter. Together with the small
`quest_vec2_t` constructor, that shape emits the same 60 instructions, keeps
template `8`, count `1`, and the active trigger in the same registers, and
resolves the player-count reference.

The remaining residual is four independent VC6 scheduling positions. Three
are in the opening entry's position/register setup and one delays entry one's
template store across the following trigger/position work. The candidate
scores 93.33% without artificial dependencies or register forcing.

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

## 2026-07-29 typed lifetime and helper pass

Seven recorded sweeps evaluate 172 additional variants. The ten-variant
`entry-lifetime-boundary-mutations.json` sweep first identifies a typed entry
one boundary, raising the score to 82.05%. The 32-variant
`entry-one-winner-interactions.json` sweep retains the smaller independent
entry-three record boundary. The four-variant
`center-position-boundary-interactions.json` sweep then disproves the earlier
direct-field center: a typed position pointer restores the three native stack
temporary instructions and raises the candidate to 90.00%.

The 15-variant `metadata-helper-boundary-mutations.json` sweep identifies the
shared metadata setter on the final entry and removes the complete tail
residual, reaching 91.67%. All 15 single/pair whole-entry helper variants are
neutral or worse. Finally, the 48-variant
`opening-lifetime-boundary-mutations.json` sweep refines entry one from a
record pointer to a position pointer and reaches 93.33%; the complete
48-variant two-entry metadata-order matrix finds no further improvement.

The seven spec SHA-256 values, in that order, are
`b856fe5f9a0671630ee3faa8752911ea001d12f92471961bd7932eb5ec4ee6a8`,
`969538c175af1190008b69a11275f7bd6ff4d400891df62545ffe0305b36e782`,
`d8ca99ec5a4647530d537762832af3ef61efeb29a5edbfe7b7df60651289b7aa`,
`84b2256c284fe144a70aae6fc465075860005c8b87ec61c991284bbab8083f23`,
`d8ca1bf376e8e748507480795a58348522e36729de2292e95b6116259dedbb4b`,
`7dacf2336d082b4ddb281708e7c71498435ec1ca27f92d953af50da2be96f696`,
and
`15d54422e008202778d3bc110bae4b3a2919aca6e43aa70b5edb925e45962bb8`.

MSVC 6.0, 6.5, and 6.6 tie at the retained 232.4/249 weighted bytes;
6.5 Processor Pack falls to 91.67% and 7.0 to 60.00%. `/G5`, `/G7`, `/Ox`,
`/Ob1`, and `/Ot` are byte-neutral while `/G6` regresses to 61.67%. The final
gap is 16.6 weighted bytes with 60/60 instructions, prefix eight, and
references 1/0/0.
