# IV merge with user cursors and index loops

This note extends [strength-reduction.md](strength-reduction.md) §3 and
[iv-anchor-examples.md](iv-anchor-examples.md). Rule A (the champion is the last preheader init, challengers come in
reverse preheader order, the challenger wins ties, the winner carries every count it absorbs) is unchanged. What is
new is how a **basic IV initialised before the preheader** takes part (a hand-written `++candidate` cursor, or the
loop index), and which pairs of IVs merge #2 is allowed to compare at all. The worked case is the `player_update`
auto-target scan, whose cursor native anchors at the `active` byte (+0) while the committed hand cursor anchors at
`position.y` (+0x18).

## Mechanism

### Basic IVs get a pseudo-init at the start of the preheader (read, then confirmed by replay)

Mode 4 of `collect_iv_candidates` 0x10746fb7 runs before merge #2 (0x10746a2f) collects its worklist:

1. For every IV symbol in `g_iv_syms` that is set in the preheader's bitset at +0x2c, it walks the symbol's
   definitions. For a definition whose id is set in the preheader's bitset at +0x54 (read as: the definition reaches
   the preheader; kind-1/2 sources get one more check, not decoded), it creates `sym = <that definition's source>` with `tuple_new(0x15b, ...,
   tuple_insert_before, anchor)` and sets `iv_tag = 9` (0x1074751c). `anchor` is `**(preheader + 0x1c)`, the first
   tuple of the preheader. So the copy goes to the **start** of the preheader.
2. It then walks the preheader forward and pushes every `IV = x` whose IV has a single in-loop tag-4 definition
   (0x107475d1..0x107475fb). The worklist is LIFO, so the pseudo-inits, being first, are popped **last**.
3. When merge #2 returns, it unlinks every tuple of the preheader with `iv_tag == 9` (0x10746f7f).

Consequence: a user cursor such as `creature_t *candidate = creature_pool; do {...; ++candidate;} while (...)`, whose
init sits in the block before the preheader, is the **last challenger** of the chain. It wins only if its own use
count is at least the count the champion has accumulated by then.

### Which IVs are compared (read; confirmed by replay)

The inner loop of 0x10746a2f compares the champion `i` with a challenger `j` only when:
- `types_compatible(i->type, j->type)` (0x10746e3f);
- the step operand, the update opcode and the update block are equal, and they are not both live after the loop
  (0x10746c4f);
- the init difference `sub_10754157(j->src, i->src, IL_SUB)` folds through `sub_10754542` (0x10746bd6 / 0x10746d88).
  Observed: immediates and addresses of one global fold (`&pool+24 − &pool`, `&pool − 0`); two different globals
  (`&a − &b`) or a variable base (`record − 0`, `entry + 16` vs `&table[k]`) do not. A preheader temp `t = x + k`
  counts as based on `x`.

A challenger that fails any check goes to the retry list (`iv_retry_list_push`). A winning challenger is pushed to
the retry list too, followed by everything still on the worklist. When the worklist is empty the current champion is
final, the retry list becomes the worklist again in push order, and the next pop is the next champion.

### Use counts

A use is a tuple that reads the IV, other than its init and its tag-4 update. For a cursor, `candidate->active`
reads the cursor itself (offset 0), and so does the exit compare `(int)candidate < (int)&pool[384]`: 2 uses. Every
other field `candidate->f` is its own derived IV `candidate + f`, with one use per distinct read that survives CSE.

## Predicting the anchor from source

1. List the IVs with the same step: derived IVs in preheader order (S1: the reverse of each expression's last
   occurrence, round by round), preceded by the basic IVs with that step whose init sits before the preheader.
2. Drop pairs whose init difference is not a constant (variable bases) into separate chains.
3. Run rule A from the end of the list. The basic IVs are the last challengers.
4. Tell-tales in the output: `cmp byte [reg], 0` for an `active` test appears only when the anchor is +0; with any
   other anchor the byte is loaded as `mov al, [reg-k]; test al, al` (all 13 compiles below). The exit compare is
   `cmp reg, &pool + N*S + anchor`, or `lea eax, [reg-anchor]; cmp eax, &pool + N*S` when a hand cursor with an
   int-cast compare lost the merge.

## Acceptance tests

### `player_update` auto-target scan (fields `active` +0, `position.x` +0x14, `position.y` +0x18, `health` +0x24;
stride 0x98; `/O2 /GB`; base b882202d5 at 72.62%, refs 840/0/1)

Predictions were written before compiling. Anchors were read from the listing and confirmed by
`iv_merge_chain.py`.

| variant | IVs in preheader order (uses) | predicted | observed | whole function | refs |
|---|---|---|---|---|---|
| b0 committed hand cursor, int-cast compare | cursor #60+0 (2) · +20 (1) · +24 (1) · +36 (1) | +24: +36 → +24 tie (2) → keeps vs +20 (3) → keeps vs cursor (2) | +24, `lea eax,[ecx-0x18]` | 72.62% | 840/0/1 |
| v1 index loop, `const vec2f_t *position = &pool[i].position` declared after the `active`/`health` test | +20 · +36 · +0 · round 3 `position+4` = +24 | +0: +24 → +0 tie (2) → keeps vs +36, +20 | **+0**, loop matches native | 71.80% | **844/0/1** |
| v9 v1 with `const vec2f_t &position` | as v1 | +0, same bytes | same bytes as v1 | 71.80% | 844/0/1 |
| v11 v1 with the two assignments swapped | as v1 | +0 | same bytes as v1 | 71.80% | 844/0/1 |
| v5 v1 with only `y` through `position` | as v1 | +0 | +0 | 71.76% | 844/0/1 |
| v2 plain index loop (negative) | +20 · +24 · +36 · +0 | +36: +0 → +36 tie → keeps | +36 | 71.70% | 842/0/3 |
| v3 index loop, per-iteration `creature_t *candidate = &pool[i]` (negative) | +0 · +20 · +24 · +36 | +24 | +24 | 71.57% | 841/0/2 |
| v4 v1 with `position` declared at the top of the body (negative) | +36 · +0 · +20 · +24 | +20: +24 → +20 tie (2) → keeps | +20 | 71.70% | 842/0/3 |
| v6 only `x` through `position` (negative) | +24 · +20 · +36 · +0 | +36 | +36 | 71.70% | 842/0/3 |

All 9 predictions held. v1 is the native shape: `xor edx,edx; mov ecx,pool; cmp byte [ecx],0; [ecx+0x24];
[ecx+0x18]; [ecx+0x14]; add ecx,0x98; inc edx; cmp ecx,pool+0xe400; jl`. It also changes the x87 shape of the
`target_index` distance just before the loop to native (`fld st(0); fmul st(1); fld st(2); fmul st(3); faddp st(1);
fsqrt; fstp st(2); fstp st(0)`); every index-loop variant does this and no pointer-cursor variant does (observed, not
explained).

**Why the whole-function percentage drops.** The normalized listing names branch targets by byte offset from the
function start. v1's loop has native length; b0's was 5 bytes longer. That surplus happened to cancel a 5-byte
shortfall between the loop and 0x109b, so b0 has offset delta 0 over 0x109b..0x14b4 (about 250 instructions), and
v1 has +5 there. Raw matched lines per target region (b0 → v1): setup and loop 0x0797..0x0869 30 → 51,
0x109b..0x14b5 249 → 206, everything else −13. With labels masked the ratio goes 81.10 → 81.70%, the stock
`--structural` view 82.51 → 83.09% (changed target instructions 762 → 739), and `structural_stack_masked` 91.93 →
92.51%. The raw number will follow once the surrounding byte counts are fixed.

Remaining differences in the region after v1 (none are IV effects): the clamp `if (auto_target < 0) auto_target = 0`
compiles to `cmp [edi+0x320], ecx` / `mov [edi+0x320], ecx` because `ecx` still holds the 0 forwarded from
`scratch_pos.x = 0.0f` a few lines earlier (native reloads the vec2 from the stack and has no zero register); the
index product uses `lea ecx` instead of `lea edx`; `distance` is stored before the two `fstp` pops instead of after;
`mov [edi+0x320], edx` comes after the `fld` of `distance` instead of before; the `distance` slot is `[esp+0x24]`
instead of `[esp+0x28]`. Splitting the distance expression into `dx`/`dy` or `distance_sq` locals, or declaring
`distance` outside the loop, did not change any of these.

### Hand-cursor controls (`struct {char active; ...; float x@8, y@12, hp@16;}`, stride 24)

The loop is `item *p = pool; do { if (p->active && p->hp > 0) { sink(...); last = idx; } ++p; ++idx; } while ((int)p
< (int)&pool[64]);`. The cursor has 2 uses (the `active` read and the exit compare).

| control | fields read | predicted | observed |
|---|---|---|---|
| h1 | active, hp, y, x (as `player_update`) | derived total 3 > 2: anchor +12 | `mov esi, pool+12`; `lea eax,[esi-12]; cmp eax` |
| h2 | active, hp, x | derived total 2 = 2, tie: cursor wins, +0 | `cmp byte [esi],0`; `cmp esi, pool+1536` |
| h3 | active, x | 1 < 2: +0 | +0 |
| h4 | h1 plus a second `p->active` read after the call | cursor 3 = 3, tie: +0 | +0 |

So in `player_update` the hand cursor could only win with a third use of the cursor itself, which native does not
have. Native's +0 anchor comes from an index loop in which the only round-3 IV (`position + 4`) is the first
champion and `active`'s round-2 IV is the first challenger.

### Replay tool

`scripts/c2/iv_merge_chain.py` now adds the pre-preheader basic IVs and runs the retry-list simulation above. It
agrees with the compiler on 71/71 loops in 32 traces: the 30 `projectile_render` loops from
[iv-anchor-examples.md](iv-anchor-examples.md), the `typo_word_pick_highscore_name` and `quest_spawn_timeline_update`
traces behind strength-reduction.md, the strength-reduction controls d/g3/h4, 15 `player_update` variants and h1–h4. The previous
version agreed on 0/1 loops in each of the four typo traces (it merged IVs with different steps) and on 1/2 in the
quest witness trace.

```sh
uv run python scripts/c2/iv_trace.py <scratch-dir> --out <trace-dir>
uv run python scripts/c2/iv_merge_chain.py <trace-dir> [--loop <address-substring>]
```

## Open questions

- `sub_10754542` was not decoded. "Folds to a constant" is inferred from which pairs merged.
- The rule "not both live after the loop" and the `+0x11` bit-4 flag are not modelled. No traced loop needed them.
- Why the loop form changes the x87 shape of the separate `target_index` distance above it is not known.

## Corrections to other notes

- [strength-reduction.md](strength-reduction.md) §3, "User cursor with the same step": in
  `quest_spawn_timeline_update` the cursor `entry` does **not** take part in merge #2. Its init is a variable
  (`entry = &quest_spawn_table[entry_index]`), so the difference from the field IVs does not fold. The replay shows
  `entry` and the +20 field IV both surviving merge #2. The fields are rebuilt as `entry + k` later, by
  `strength_reduce_address_operands`, as §7(c) says.
- strength-reduction.md §3 describes mode 4 as walking only the preheader. It also inserts tag-9 copies of the
  reaching inits of pre-preheader basic IVs at the preheader start, which makes those IVs the last challengers.
- strength-reduction.md §7, "Remaining int-cast holdouts", `player_update` row: the drop in the whole-function
  number comes from branch labels moving by 5 bytes, not from IV or loop code. See the walkthrough above.
- [iv-anchor-examples.md](iv-anchor-examples.md), open question "the replay does not split IVs by step, opcode,
  update block or type": the replay now splits by step, update block and init base. The typo traces needed the
  step split.
