# Creature field-pointer operand flag 0x10

Tests the hypothesis that a front-end flag keeps the native creature field
pointers in registers or stack homes. Diagnostic only: no compiler decision is
changed and the canonical source is unchanged
(`7bb97911b09a9e96d60b4b7b93530f07702d92de55d343d75fb5b642b49f44bd`).

## Hypothesis

The later reconstruction predicate at `C2+0x527b2` refuses to rebuild an
address when a source temporary carries descriptor bit `+5 & 0x10`; the
per-operand byte `+0x11` bit `0x10` is set during expression decoding at
`0x5e1a` and `0x7476`. If some front-end construct attached that bit to the
native pointers, they would survive to receive homes.

## Observation (`verify.py`)

A preserving trace of the current source records the operand bit on the copy
nodes that define each source pointer:

| Pointer | `0xfcda` | `0x281cd`..`0x306c1` | Emitted |
|---|---|---|---|
| health, lifecycle, collision, size, cooldown | set | clear | rebuilt from ESI |
| `&target_player` | absent (copy not yet formed) | set from `0x2930f` through `0x30308` | never formed; 13 direct `[esi*8+0x70]` accesses |

Descriptor bit `+5 & 0x10` never appears before allocation.

So the flag cannot be the retention cause. It is present on the one pointer
native keeps in EBX, yet this candidate still drops that pointer and addresses
the byte directly. The five field pointers native homes lose the flag in
`0x281cd` and are dropped too. Presence and absence both end in the same
result.

## Use-count control

Native reloads the target byte through EBX at six sites in the contact block
(`0x0042721a`..`0x004273cd`). Routing all six contact-block reads through
`*target_player` (with the pointer already declared) still emits no
`lea ebx`: 16 direct accesses, frame `0x68`, 63.52%. A standalone control with
pointers of float, int, signed char, and unsigned char type, each read across
four calls under register pressure, likewise emits no pointer register. Use
count and pointee type are not sufficient.

## Conclusion

Rejected: neither operand flag `0x10` nor more uses of the declared pointer
keeps these pointers. This agrees with the
[review](../creature-pool-review-2026-09-23/README.md): `0x10` on a descriptor
marks an already performed regional split. The remaining causal question is
the dependency graph that native used: which source value the pointer depends
on, and whether a non-rematerializable dependency (for example a pointer read
from memory, not computed from the loop index) made native keep it.

```sh
uv run --no-sync python \
  tools/match/evidence/creature-pointer-flags-2026-09-23/verify.py --out /tmp/<fresh-dir>
```
