# `quest_build_lizard_kings`

Native target: `crimsonland.exe` at `0x00437710` (254 bytes).

Live Binary Ninja evidence recovers three initial template `0x11` lizard
formations at `(1152, 512)`, `(-128, 512)`, and `(1152, 896)`, all at 1500 ms
with count one. They are followed by 28 template `0x31` lizards on a radius-256
ring centered at `(512, 512)`. The ring step is `0.34906587` radians, triggers
start at 1500 ms and advance by 900 ms, and heading is the independently
recomputed negative ring angle. The final count is 31.

The candidate reproduces the fixed-entry vector temporaries and the complete
native x87 ring stack: the integer index remains live below the positive angle,
cosine and sine consume the duplicated angle, and the original index is then
multiplied by the negative step for heading. The three fixed entries now publish
through one append count. Each following position is constructed while the
current entry's metadata remains live, and the ring index begins before the
third count is published. The retained source models the native template-field
induction pointer directly and emits the same 66 instructions, with all six
constant references resolved. Its current weighted match is 87.88% with a
13-instruction exact prefix.

The fixed prefix now differs by only one independent load placement. The larger
remaining residual is the x87 ring body: the template cursor removes the former
loop-invariant `mov edi, 0x31`, but VC6 still schedules ring metadata and loop
updates around the trigonometric stack differently. Direct position fields,
all-fields and metadata-only setters, compiler profiles, cursor views, member
access, pointer-advance placements, fixed-value lifetimes, and helper orders
are bounded without artificial dependencies, so this remains an honest WIP.

## Binary Ninja loop recovery

The authoritative map now types the `xor edx, edx` definition as the integer
`angle_index` and the native `&entries[3].template_id` induction value as a
`quest_spawn_entry_template_cursor_t *`. A live replay removes Binary Ninja's
former invented `quest_spawn_entries_binja_t *i = nullptr` loop variable,
recovers `angle_index += 1` and the signed `< 28` backedge, and exposes the
cursor's exact 24-byte entry stride.

VC6 reuses the original `entries` argument stack slot as the integer index
spill and advances the template cursor one record before the loop stores. That
still leaves a misleading `table = angle_index` assignment and negative raw
offsets in HLIL. A layout-equivalent 36-byte one-ahead view containing the
previous entry plus the next position was tested live, but Binary Ninja kept
all six negative offsets instead of presenting `previous` fields. The durable
map keeps the narrower types that improve the recovered control flow without
claiming the remaining decompiler artifacts are source structure.

## Recovery classification audit

The live Binary Ninja loop and fixed prefix account for all 31 entries, ring
constants, trigger recurrence, heading computation, and final count. The
candidate emits 66 instructions against 66 native instructions with `6/0/0`
references. `--regions` attributes the remaining delta to VC6
allocation/scheduling, not missing quest policy. Recovery is
`semantic-complete` with a `compiler` residual.

## Exact-tail follow-up (2026-07-27)

The five-compiler and six-flag matrices retain the ordinary VC6 `/O2 /GB`
profile; VC7, `msvc6.5pp`, and `/G6` regress. Recorded source-shape and
helper-order sweeps evaluate 53 variants across cursor/trigger order, scalar
versus `pos.set` ring stores, metadata fields, loop-update order, index scope,
and independent fixed/ring helper permutations. None improves the
`198.61654135338344/254` weighted bytes, 67/66 instructions,
seven-instruction prefix, or `6/0/0` references. The remaining extra
loop-invariant template register was therefore still a compiler residual at
that checkpoint.

## Template-cursor boundary audit (2026-07-30)

Live inspection identifies the native induction value as a
`quest_spawn_entry_template_cursor_t *`. Three new bounded sweeps test that
constraint after the adjacent lizard-builder recoveries:

- `template-cursor-mutations.json` evaluates five cursor views. The
  current-record template cursor is the sole improvement: it removes the extra
  invariant template instruction and moves weighted bytes from
  198.617/254 to 200.121/254 (78.788%). One-ahead, entry-cast, and dual-cursor
  views regress.
- `template-cursor-member-access-mutations.json` evaluates seven struct-member,
  setter, pointer-advance, heading, and count placements. Four are byte-neutral
  and three regress, so no additional source change is retained.
- `post-template-fixed-lifetime-mutations.json` evaluates 41 combinations of
  fixed-value lifetimes and fixed-helper store order. All are neutral or worse.

The ledger now contains five records and 106 evaluated unique variants, with
one improving variant and no exact winner. The retained source has 66/66
instructions, a seven-instruction prefix, and references 6/0/0. Source
SHA-256: `fb6a655e181465a4cdb07211f7c558e387190c2b193e75de987d95c4e8273a55`.
Experiment ledger SHA-256:
`ea064d53f789c16d9ec1f0004dacc24221941c739b32341c1284cbebfaec5d29`.

## Staged-prefix recovery (2026-08-08)

Replaying the fixed-table publication style recovered in adjacent quest
builders improves the score from 78.79% to 87.88%. One continuous append count
owns the three fixed entries; the next named position is constructed before the
current trigger/count publication; and the zero ring index is introduced before
the third fixed count. The change preserves 66/66 instructions and `6/0/0`
references while extending the exact prefix from seven to 13 instructions.
Split-component positions and typed count pointers are byte-neutral, and a full
aggregate ring setter regresses, so only the staged prefix is retained.
