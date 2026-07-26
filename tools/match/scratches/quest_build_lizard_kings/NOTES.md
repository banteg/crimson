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
multiplied by the negative step for heading. `pos.set(x, y)` avoids a dynamic
vector temporary and raises the candidate to 78.20%, with 67 instructions
against 66 and all six constant references resolved.

The residual is one loop-invariant `mov edi, 0x31`. The native instead stores
the template as an immediate and consequently chooses the template field as
its pointer induction base. Direct position fields, an all-fields setter, a
metadata-only setter, `msvc6.5pp`, and `/G6` were checked. None removes that
allocation without degrading the proven x87 shape or adding an artificial
dependency, so this remains an honest WIP.

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
candidate emits 67 instructions against 66 native instructions with `6/0/0`
references. `--regions` attributes the remaining delta to VC6's loop-invariant
template register and related allocation/scheduling, not missing quest policy.
Recovery is `semantic-complete` with a `compiler` residual.
