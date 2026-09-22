# Creature pool base pointer and native addressing units

`creature_update_all` now reaches the native scaled creature addressing
(`[esi*8 + creature_field]`) with stock `msvc6.5 /O2 /GB /W3 /GR-`. The
[offset-unit investigation](../creature-offset-units-2026-09-22/README.md)
showed that the previous extra `shl esi,3` is chosen before register
allocation. This package identifies the source form that avoids it.

- Before source SHA: `b27f450cd219a514e9083ddfb87842a3a960130f6d5343b851ae6f7835b9ddae`
- After source SHA: `7bb97911b09a9e96d60b4b7b93530f07702d92de55d343d75fb5b642b49f44bd`
- Alignment 58.55% to 66.67%; 1,306 to 1,311 of 1,338 instructions;
  references `226/0/1` to `363/0/5`. The frame is `0x6c` against native `0x7c`.
  Neither exactness flag is claimed.

## Addressing unit control

Stand-alone VC6 controls with a 152-byte element separate the two forms:

| Source form | Emitted addressing |
|---|---|
| `pool[i].f`, `(pool + i)->f`, `(&pool[0])[i].f` | `lea;lea;shl 3`, `[reg + pool+f]` |
| sized/unsized/static/member arrays, `unsigned`/`short` index, inline accessor | same shift |
| `C *P = pool; P[i].f` (also `C *const`, `C (&P)[385]`) | `lea;lea`, `[reg*8 + pool+f]` |
| single use of `pool[i].f` | scaled (no shared offset formed) |

With a local base pointer the address stays `base + 8*(19*i)`, which is the
native opening sequence and all 190 native current-creature accesses. The
retained source declares `creature_t *creatures = creature_pool;` beside the
loop index and indexes it for the current creature.

## Separate owners

Native addresses the linked creature through the shifted form in the
follow-link and tethered arms (`shl ecx,3` at `0x004267e4` and
`0x00426849`) but scaled in the orbit-link arm. Keeping `creature_pool` for
the first two and the pool base for the others reproduces both. The link-guard
arm has one access and compiles identically either way; it uses the global
name. The auto-target lookup was byte-neutral and keeps `creature_pool`.

## Local shapes recovered after the addressing change

With scaled addressing in place, several regions became locally comparable.
Each change below makes its native window instruction-identical except for
stack displacements and branch labels:

- tethered-link distance uses the existing `creature_vec2_length` over a
  target/position vector difference (native keeps both deltas on x87);
- alternate-player health and position index `1 - current_player_index`,
  matching native's reuse of the widened target byte;
- the link timer updates `link_index` in place, giving native's hoisted
  `frame_dt_ms` load and `jl` test;
- the hold-timer target copy is a vector value copy (native loads both words
  before storing either);
- the forced-target publication is a `target_position` aggregate assignment.
  The three far-orbit copies keep component assignments: every combination
  of converting them regresses (seven variants).

## Behavior

`verify.py` rebuilds both sources and executes all 3,480 existing fixtures
(2,472 historical, 768 retarget, 192 interaction, 48 corpse) against native
x86 with the existing callback models. Both sources have zero differences in
state, players, slots, scalars, ordered writes, model writes, and calls.

```sh
uv run --no-sync --with unicorn==2.1.4 python \
  tools/match/evidence/creature-pool-base-2026-09-22/verify.py --out /tmp/<new-dir>
```

## Remaining residual

Native stores four field pointers (lifecycle at `+0x24`, the byte at `+0x28`,
collision flag at `+0x30`, cooldown/size at `+0x14`) and keeps
`&target_player` in EBX; the candidate rematerializes those addresses from
ESI. In a full preserving trace every pointer definition is still present
(`0x12` LEA plus copy) at the entry of `C2+0x306c1` and gone at `0x30a40`,
as the earlier health-pointer study found. Declaration placement, element
pointers, block scope, global-pool initializers and byte arithmetic all
compile to the same body. The five reference mismatches are pairing effects
of this allocation difference: target Y/X store order, heading versus orbit
angle, and the adjacent perk/SFX calls.
