# `quest_build_the_end_of_all`

Native target: `crimsonland.exe` at `0x00438e10` (692 bytes).

Live Binary Ninja evidence recovers a fixed 1024-by-1024 quest script whose
headings are left untouched:

- four template `0x3c` corner spiders at (128,128), (896,128), (128,896),
  and (896,896), with triggers 3000, 6000, 9000, and 12000 ms;
- six template `0x07` spawners on a radius-80 ring around (512,512), using
  angle `index * 1.04719758`, triggers 13000 through 14500 ms by 300, and
  count one;
- one template `0x0b` spawner at (512,512), trigger
  `ring_index * 300 + 13000` (14800 ms), count one;
- four template `0x3c` spiders alternating x -128/1152 at y 256, 384, 512,
  and 640, with triggers 18000 through 21000 ms and count two;
- another six template `0x07` radius-80 spawners, now using angle
  `index * 1.04719758 + 0.52359879`, triggers 43000 through 44500 ms;
- in hardcore mode only, twelve template `0x07` radius-180 spawners using the
  observably ordered angle `(index + 1) * 0.52359879`, triggers 62800 through
  68300 ms by 500;
- a final four-entry alternating spider batch with triggers 48000 through
  51000 ms. It starts at index 21 normally or index 33 in hardcore mode, so
  the final counts are 25 and 37 respectively.

The native hardcore branch and fixed coordinate space corrected three port
assumptions. The optional radius-180 ring is keyed to hardcore rather than
full-version status, quest coordinates do not scale with the runtime terrain,
and the hardcore angle operation order changes two f32-truncated coordinates.

The candidate reproduces 173 of the native body's 174 instructions and all 18
audited references, scoring 66.28% with a four-instruction exact prefix. A
position member setter is important: it retains the ring angle across `fcos`
and `fsin` exactly like native. Expressing the center trigger from the completed
ring index also recovers the native multiply-by-300 LEA chain.

The residual is consistent VC6 induction-base and register allocation. Native
anchors each loop cursor at `template_id`, preadvances it, and addresses the
position and metadata through negative offsets; the candidate anchors the same
24-byte cursor at the record start. Native also uses ESI for the initial
template constant and hoists count two into EBP, while the candidate uses EBP
for the template and emits the count immediate. A combined vector-and-metadata
setter, metadata-first order, and explicit preincrement cursor all scored worse.
No artificial dependencies, volatile state, or register-forcing constructs are
used.

## 2026-07-27 focused profile and mutation pass

MSVC 6.0, 6.5, and 6.6 tied at 66.28242074927954%. The 6.5 Processor Pack
profile regressed to 59.94% with 13 matched references; MSVC 7.0 fell to
32.29% with references 6/3/0. `/GB`, `/G5`, `/G7`, `/Ox`, and `/Ob1` tied,
while `/G6` regressed.

`opening-local-lifetime-mutations.json` (SHA-256
`e0c73992addd25fd3e12e3255968268b8fd1d515ed72995c0d4a1a856625f202`)
recorded five complete variants, all byte-neutral. No source change was
retained. Fresh validation remains at 458.6743515850144/692 weighted bytes,
a 233.3256484149856 gap, 66.28242074927954%, 173/174 instructions, prefix
four, and references 18/0/0.
