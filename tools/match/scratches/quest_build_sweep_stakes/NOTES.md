# `quest_build_sweep_stakes`

Native target: `crimsonland.exe` at `0x00437810` (258 bytes).

Live Binary Ninja evidence recovers sixteen waves of four template `0x36`
orbiters. Each wave chooses one angle as `(crt_rand() % 612) * 0.01` and emits
radii 84, 126, 168, and 210 around `(512, 512)`. Heading is the angle from the
center minus half pi. Trigger time starts at 2000 ms; its step also starts at
2000 ms, contributes at least 600 ms, decreases by 80 after each wave, and
continues while the reduced step is greater than 720. The native writes the
constant final count 64.

The candidate reproduces the signed remainder, 24-byte frame, saved cosine and
live sine, two-stage rounded vector construction, `fxch`/`fpatan` heading,
nested loop boundaries, trigger clamp, and all seven references. It compiles
to 75 instructions against the native 76 and scores 76.82%.

The structural residual is one `add entry_cursor, 16`: the native selects
`trigger_time_ms` as its induction base, while VC6 selects the record start for
the same source and schedules the three independent metadata stores earlier.
A post-incremented spawn pointer, direct fields, an explicit trigger-cursor
view, `msvc6.5pp`, `msvc6.6`, `msvc7.0`, and `/G6` were checked. The explicit
view recovers the offset but damages the proven x87/vector shape or frame and
does not improve the score. This remains an honest WIP without encoding the
optimizer's negative-field cursor into the source.

## Recovery classification audit

Binary Ninja confirms the complete 16-wave policy, random angle, four radii,
heading, trigger clamp, entry metadata, and final count. The candidate emits 75
instructions against 76 native instructions with `7/0/0` references. The
localized regions reflect only the trigger-field induction anchor and
independent-store/x87 schedule described above. Recovery is classified
`semantic-complete` with a `compiler` residual.

`typed-trigger-cursor-mutations.json` records all fifteen single and combined
typed-cursor choices. The complete combination falls to 59.46%, and none
improves the 75.50% baseline, confirming that the negative-field cursor would
trade away the proven vector/x87 structure.

## Exact-tail follow-up (2026-07-27)

The five-compiler and six-flag profile matrices keep the VC6 `/O2 /GB` family
best. `/G5`, `/G7`, `/Ox`, and `/Ob1` are code-identical here; `/G6` and VC7
regress. A recorded 47-variant source-order sweep found one independent gain:
declaring trigger time and trigger step before the entry cursor changes VC6's
allocation without changing the quest policy. The retained ordering raises
weighted bytes from `194.7814569536424` to `198.19867549668876`, reduces the
gap from `63.21854304635761` to `59.801324503311236`, and preserves the
75/76 instruction counts, six-instruction prefix, and `7/0/0` references.

A five-variant helper-store-order follow-up found no additional improvement.
The complete sweeps are recorded in `experiments.jsonl`; the remaining
localized delta is still the native trigger-field induction anchor and x87
scheduling described above.
