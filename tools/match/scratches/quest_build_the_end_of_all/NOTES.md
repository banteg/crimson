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

The recovered source matches all 692 native bytes and all 174 instructions,
including the full instruction prefix and all 18 audited references. One
continuous append count replaces six hardcoded phase cursors and both fixed
final-count assignments. Direct indexed publication then gives VC6 the native
template-id induction bases without negative-field cursors or artificial
dependencies.

The first corner's template and count lifetimes recover the native prologue,
while a separate declaration and assignment for the first ring index preserves
the native transition into the ring loop. Position setters retain each ring
angle across `fcos` and `fsin`; the center entry deliberately publishes its
metadata through direct fields, which is the final source-shape distinction
needed for the exact build.

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

## First-entry lifetime and store audit

Native disassembly materializes the first position before loading the shared
template/count registers. `first-entry-lifetime-mutations.json` (SHA-256
`0825c42d731a0c3d52eb56fec9b658118f18bb331c5301766649825201676a2b`)
tested moving either or both semantic constants to that boundary.
`first-entry-store-shape-mutations.json` (SHA-256
`df6e342a1be59dd2b5436226185037319515c36e4ede6172922e13d690ed21d0`)
separately tested direct position, metadata, and all-field stores. All seven
variants were byte-identical, confirming that VC6 erases these source-level
distinctions. The canonical source and 66.2824% score remain unchanged.

## 2026-08-08 exact recovery

The committed baseline scored 458.6743515850144/692 weighted bytes
(66.28242074927954%), with 173/174 instructions, prefix four, and references
18/0/0. Replacing the phase-specific cursors with one append count, publishing
loop entries through direct indexing, and preserving the native opening-local
lifetimes raised the candidate first to 97.13% and then 98.28%.

`edge-local-order-mutations.json` (SHA-256
`3f2f105d9df6ecc46d7540bbbf7611335919a23a0eab5c30cb61fbd3dc5840e3`)
recorded seven byte-neutral first-edge declaration orders.
`final-edge-local-order-mutations.json` (SHA-256
`f3342fb121299eb0f760fc04dc144413eb007f6daccfd04af026da1a238e2334`)
identified `index-trigger-edge`, an eight-weighted-byte improvement to 98.28%.
Finally, `center-metadata-publication-mutations.json` (SHA-256
`b4a7f31e12dc0c6092d2bea86500aa64ed5be42a85122c98c200b57f3029e78e`)
confirmed that direct center metadata fields recover the remaining 12 weighted
bytes. The exact source SHA-256 is
`c22882d9af4314ebcfaa82e072ebd17aa8222176bbd398dc0b5cb666e115d8e0`.
