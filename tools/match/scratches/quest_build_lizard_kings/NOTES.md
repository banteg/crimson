# `quest_build_lizard_kings`

Native target: `crimsonland.exe` at `0x00437710` (254 bytes).

Live Binary Ninja evidence recovers three initial template `0x11` lizard
formations at `(1152, 512)`, `(-128, 512)`, and `(1152, 896)`, all at 1500 ms
with count one. They are followed by 28 template `0x31` lizards on a radius-256
ring centered at `(512, 512)`. The ring step is `0.34906587` radians, triggers
start at 1500 ms and advance by 900 ms, and heading is the independently
recomputed negative ring angle. The final count is 31.

The recovered source reproduces the fixed-entry vector temporaries and the
complete native x87 ring stack: the integer index remains live below the
positive angle, cosine and sine consume the duplicated angle, and the original
index is then multiplied by the negative step for heading. The three fixed
entries publish through one append count. The ring uses the original indexed
record spelling, `spawns[entry_count + angle_index]`; VC6 strength-reduces it to
the native 24-byte induction pointer, advances that pointer inside the x87
window, and delays metadata publication until both coordinates are complete.
The result is exact at 66/66 instructions and 254/254 bytes, with all six
constant references resolved.

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
references and no residual regions. Recovery is exact.

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

## Complete-entry house-style improvement (2026-08-09)

Completing the first fixed record's trigger and count before declaring the next
position transfers the exact pattern from Army of Three and Land of Lizards.
VC6 schedules the following constructor between the shared count-one load and
the record stores, matching the whole fixed table. The score rises from 87.88%
to 89.39% and the exact prefix from 13 to 38 instructions; the independent ring
loop remains unchanged at 66/66 instructions and references `6/0/0`.

## Indexed-ring exact recovery (2026-08-09)

The exact Gauntlet ring established the missing house-style distinction:
repeated `spawns[index]` expressions keep metadata publication behind both
coordinate calculations, while a retained record or field cursor lets VC6
hoist those stores ahead of the trig stack. Expressing this ring as
`spawns[entry_count + angle_index]` also avoids a second incrementing record
index. VC6 derives the native pointer advance after `fild`, retains the ring
index for the late negative-angle heading, and emits the target's metadata and
loop-update schedule exactly. The score rises from 89.39% to 100%, the exact
prefix from 38 to 66 instructions, and references remain `6/0/0`.
