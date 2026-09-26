# Reading native's stack objects from its slot partition (C2.DLL 8966)

This note describes a method for recovering the stack objects a native function had. It maps every
native frame reference to a candidate stack object, then reads the native slot partition against the
candidate's interference graph. The result is a list of source-level objects that native has and the
candidate lacks, or the reverse.

The note also records the liveness rule that makes the method work: a local whose definitions never
kill it is live across its whole enclosing loop.

The worked case is `projectile_render`. The native frame is 0x19c, and 220d4188f is 0x184. Addresses
are virtual addresses in the pinned C2.DLL (image base 0x10700000), for `/O2 /GB`.

Evidence labels:
- **Verified**: observed in a compile or in the preserving observer of
  [`frame_predict.py`](../../../../scripts/c2/frame_predict.py).
- **Inferred**: fits every compile below but was not traced.

See also:
- [frame-model.md](frame-model.md), for weights, list order, the packer and the density sort;
- [per-arm-frame-weights.md](per-arm-frame-weights.md), for the rule that a field store does not kill;
- [slot-sharing-symbols.md](slot-sharing-symbols.md), for why function-scope aggregates block sharing.

## 1. Tool

```sh
uv run python scripts/c2/native_slots.py tools/match/scratches/<name> --out /tmp/<new-dir> [--source v.cpp] [--json p.json]
```

The tool compiles through the preserving observer and through a `/FAsc` listing, which is
object-equivalent. The listing names the candidate object behind every `[esp+N]`. Anonymous temps
are resolved by offset and source line.

The tool aligns candidate and native instructions with difflib over normalized text. Each aligned frame
reference votes "object X lives at native bottom B". The member offset inside X is subtracted, so a
`.y` reference votes for the object base. It prints three things:

1. **The native partition.** For every native object base it lists the candidate objects voted there,
   with their candidate offset, weight and vote count. In brackets it lists every candidate
   interference edge between two members of the same native slot. A bracketed edge is a liveness fact
   that native does not have.
   - `(field +k of the native object at B)` means a candidate object voted into the middle of another
     native object. Either native has an aggregate there, or the candidate object is larger than
     native's.
2. **Native frame references with no candidate object.** These are objects the candidate lacks, such as
   a spill, or code the alignment could not pair.
3. **The packer replay in the candidate's list order.** Each placement whose slot mates live in
   different native slots is marked `<<`. The first `<<` is normally the one to fix. Later marks are
   usually its cascade.

## 2. Liveness rule: objects that are never killed are loop-wide [verified]

The packer's interference comes from backward liveness. At each definition,
`interf[def] |= live` ([frame.md](frame.md) §1.3). A definition kills only on a whole-object store
(0x1074b45e; that address is static, not traced). Two kinds of store do not kill in practice:

- **Integer-typed stores to a float local.** Under /Ot, lowering writes float constant stores and
  float copies as integer moves. Examples are `x = 1.05f;` → `mov dword [x], 0x3f866666`, and
  `span = distance;` → `mov eax,[distance]; mov [span],eax`. That store operand is an integer view
  of the float symbol, not the symbol itself.
- **Field stores to an aggregate.** This is rule 4 of [per-arm-frame-weights.md](per-arm-frame-weights.md).

A local whose every definition on some path is of this kind is live at the header of its enclosing
loop. It therefore conflicts with every object defined anywhere in that loop, including code before
its own block. In `projectile_render`:

- `effect_scale`, both copies, is defined only by `mov [m], imm`. Each copy conflicts with 43 objects
  of the ion loop (named locals and anonymous temps, `$T` aggregates not counted), including
  `pulse_scale` and the splitter and blade `size`. Those are defined in
  earlier `continue` arms of the same loop.
- `along`, `span` and `first` of both ion blocks are loop-wide too. `along = 0.0f` is an integer
  store, and `span = distance` and `first = along` are integer copies.
- `strip0..3`, `arc`, `direction`, `direction_result`, `start_result` and `end_result` are loop-wide
  because they are written by field stores.
- Locals defined by `fstp`/`fst` are killed and conflict only locally. These are `distance`, `step`,
  `half_size`, `fade` and `radius`.

The conflicts stop at the loop boundary. Every loop-wide ion object shares a slot with objects of the
conventional-trail or plasma loops, which run earlier. The data-flow reason why the liveness does not
reach back before the loop was not traced; see open questions.

**Consequence.** Two loop-wide objects of one loop can never share a slot. If native puts two such
candidate objects in one slot, native had one object: a single variable reused by both blocks.

## 3. How to read native's objects off the partition

Take each native slot and the candidate objects voted into it:

1. **Bracketed conflicts between loop-wide members.** Merge them into one source variable declared
   around both uses (§2).
2. **A member referenced only at +4 or +0xc of an FPO slot.** FPO members sit at the slot base
   ([frame-model.md](frame-model.md) §4). A reference that lands elsewhere is therefore a field of a
   native aggregate. Rebuild the aggregate:
   - Separate floats `base_x`/`base_y` voted to 0x8c/0x90 mean one vec2 `base`.
   - A 4-byte `fade` referenced only at bottom 0x168 means field +0xc of a 16-byte object at 0x15c.
3. **Check density order.** Final reference counts approximate the weights within 0 to 4. A slot that
   breaks the descending density order may be larger than it looks. The 0x15c object has weight 7
   over 16 bytes, density 437. That is the only size that fits between the 500 slots below it and the
   250 slots above it.
4. **Native references with no candidate object.** Such an object is missing from the candidate. In
   the ion loop, `lea edi,[ebx-0x14]; mov [esp+0x38],edi` and three reloads are a class-3 home of the
   `projectile` pointer. The candidate forward-substitutes that pointer into `ebx`-relative operands
   ([frame-model.md](frame-model.md) §5).
5. **Only then look at list order.** A native partition that the candidate's conflicts allow but its
   list order misses is a weight or tie question ([frame-model.md](frame-model.md) §2).

## 4. Acceptance tests

Each test is a copy of 220d4188f's scratch plus the changes of the previous rows. The predictions come
from the partition and §2, and were written before the compile. The replay lines and the conflicts
come from the observer.

| # | Change | Prediction | Observed |
|---|---|---|---|
| 1 | `effect_scale` of the 0.4 block defined by `transition_alpha * 2.0f` (fstp) instead of four constant stores (diagnostic only) | loses its conflicts with the killed locals of the other arms: `pulse_scale`, the splitter and blade `size`, `fade`, and the fading block's `distance`, `step`, `radius`, `head_alpha` and `old_arc_x`. It keeps the loop-wide objects and its own block's locals | against those names, 13 conflicts before and 4 after: its own `distance` and `step`, and both `half_size`s, the arc-loop one being a hoisted copy. The loop-wide objects (`along`, `span`, `first`, the strips, the `$T` aggregates) remain. Negative control: the fading block's `effect_scale`, still defined by constant stores, keeps `pulse_scale` and `size` |
| 2 | one `float scale` for `pulse_scale`, splitter `size`, blade `size` and both `effect_scale`s | a single object, weight 32, that no other ion-loop object joins; one conventional-trail `$T` joins it (native bottom 0x14) | `_scale` w32 plus one conv `$T` only |
| 3 | one `direction` vec2 for both ion blocks and the arc loop (`arc` removed) | one object, weight 23, with no other ion-loop object in its slot. Native 0x44 has no other member | w23. Its only slot mate is a first-loop `$T` |
| 4 | one `distance` for both blocks | the shared `distance` conflicts with `fade` through the fading block, so it opens its own slot; the 0.4 block's `step` then joins `fade` (native 0x8) | `distance` new slot, `radius` joins it; `step` joins `fade` |
| 5 | one function-scope `int segment_index` for the five plasma loops | weight 15 right after `fade` (16) and no conflict with it, so it joins `fade`'s slot (native 0x8) | joins slot 1 with `_fade` |
| 6 | conv-loop clamp in `effect_color_t trail_color; trail_color.a` | 16 bytes, weight 7, density 437; sorted between the weight-4 8-byte slots and the weight-2 ones | slot 46, density 437, between them |
| 7 | plague `float phase` instead of `double` | a 4-byte object in the push-temp slot (native 0x10) | joins that slot |

## 5. Result on projectile_render

| Variant | Frame | Match | Refs | Stack-masked structural | Objects at native offset |
|---|---|---|---|---|---|
| 220d4188f | 0x184 | 73.35% | 532/0/0 | 96.49% | 38/175 |
| + AR head + fading-beam alpha (combo1) | 0x188 | 71.19% | 538/0/0 | 96.98% | |
| + rows 2–7 except 5 (`best.diff`) | 0x194 | **74.17%** | **537/0/0** | 97.56% | 42/174 |
| + row 5 | 0x194 | 72.60% | 529/0/2 | **97.83%** | |

The stack-masked score rises with every native object recovered. The canonical score depends on
where the unsorted remainder lands.

The frame is still 8 bytes short:
- native's 0x028 slot is created by the `projectile` spill (§3 item 4);
- one more 4-byte slot is grown to 8 in native (0x054 or 0x094).

The full slot map is in the work directory as `slot_map.md`.

## 6. Open questions

- Why loop-wide liveness does not extend before the loop. A never-killed local should also be live on
  the loop's entry edge. A hook on the liveness walk (0x1074ac4c / 0x1074b107) would show where the
  bit is cleared.
- Which source keeps the ion-loop `projectile` pointer as a spilled range. Rewriting the first read as
  `projectile_pool[projectile_index].active` and making the pointer function-scope both left the
  object byte-identical.
- In native, the conventional-trail staging temps (weight 8) join `along`'s slot, not the shared
  `half_size` slot (weight 10). With the candidate's weights the packer places `half_size` first. So
  either native `half_size` weighs at most 8 at layout time, or the staging temps weigh more before a
  later peephole.
