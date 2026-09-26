# quest_spawn_timeline_update: the dead pointer-store triplet (C2.DLL 8966)

Native `quest_spawn_timeline_update` (0x00434250) has three instructions that the canonical scratch
lacks, right after the positive-count guard:

```asm
lea  edi, dword [esi+0xc]      ; &entry->template_id, kept in edi through the spawn loop
mov  dword [esp+0x10], edi     ; dead store
mov  dword [esp+0x10], ebx     ; spread = 0, same slot
```

This note says which C2 steps produce each instruction, what compiler state produces all three, and
why no ordinary source reaches that state. It builds on
[post-promotion-stores.md](post-promotion-stores.md), [constant-candidates.md](constant-candidates.md)
§4, [unfolded-field-pointers.md](unfolded-field-pointers.md) and the scratch NOTES. Addresses are
virtual addresses in the pinned C2.DLL (image base 0x10700000), `/O2 /GB`.

Evidence labels:
- **Verified** means seen in a preserving trace, or in a diagnostic run whose object was scored.
- **Read** means static reading in Binary Ninja.
- **Inferred** means neither.

## 1. Short answer

1. **The store is a dead definition of a 4-byte local that `build_live_ranges` demotes.** A
   promoted local X gets the definition `X = p`, where p is the pointer temp. X has no reads left.
   At the end of the block, `insert_upward_exposed_reloads` 0x1072e7cb (call site 0x1072eb81)
   passes X to `demote_unused_candidate_def` 0x107318e5, which rewrites the definition as a memory
   store (`operand_make_sym`). No pass deletes a dead memory store after the global optimizer, so
   the store survives. [verified]
2. **The `lea` survives because the store is a value use of p.** In
   `forward_substitute_single_def_ranges` 0x107306c1, phase 1 excludes a range that is used as a
   value (`lr+5 |= 4`). The same flag stops the later `try_substitute` path. p is not folded back
   into `[esi+k]` operands and gets `edi`. [verified]
3. **[esp+0x10] is X's slot, shared with `spread`.** At frame layout X has one store and no reads.
   It conflicts with nothing that is live at its store, so the packer puts it in `spread`'s slot.
   `spread = 0` is the next instruction. [verified in the witness, frame 0x1c]
4. **The whole compiler state that gives native.** A diagnostic intervention at `build_live_ranges`
   entry makes the named pointer's definition dead and moves its reads to the pointer temp.
   Applied to a heading-through-pointer spelling of the scratch, it produces a `.text` that is
   **byte-identical** to the September 13 stock witness. With the y-coordinate base also moved to
   `entry`, the only differences from native left are the zero constant's register and the branch
   labels that follow from it (§4). [verified]
5. **No stock source was found that reaches that state, and the globopt schedule explains why.**
   X's definition has to survive `globopt_run`'s last dead-code pass (0x10713683) while its last
   read disappears later. The only step after that pass that deletes a read is the flow-graph rebuild
   at 0x107136f2. Before that point, copy propagation and value numbering already rewrite every
   read of a plain copy of p. So X's value has to come from a copy the optimizer cannot see
   through. The known ways are the copy intrinsic 0x190 (a byte loop, or `memcpy` with a variable
   size) and `volatile`. [read, and verified by the controls in §5]
6. **The idiom is unique in the corpus.** `demotion_scan.py` ran on all 1244 scratch sources (807
   of them byte-exact). It found no other named scalar local whose definition is demoted and never
   read again. Every other hit is read back from memory: `fild` of an int local, float bit views,
   or aggregate lanes. [verified]

## 2. Which step makes each instruction

| Native instruction | Owner / range | Made by | Why it survives |
|---|---|---|---|
| `lea edi,[esi+0xc]` | pointer temp p (witness `#216c3`, entry + 12) | lowering (IL `+` becomes `lea` 0x12) | phase 1 of 0x306c1 excludes p (value use `mov X, p`). fsub_trace verdict on the witness: `lr 24 #216 lea … kept: phase 1` |
| `mov [esp+0x10],edi` | local X (witness `_copied`, `#13c4`) | 0x107318e5 from 0x1072eb81: the def `X = p` is pending at the block end and X is not live-out | `late_register_value_cse` removes only loads, and `late_stack_temp_forwarding` removes only class-3 pairs ([post-promotion-stores.md](post-promotion-stores.md) §3.1) |
| `mov [esp+0x10],ebx` | `spread` (int read by `fild`, stored back and demoted) | the `spread = 0` definition, whose value is the shared zero in `ebx` | live: read by `fild` in the loop |

The witness trace (`const_trace.py`, block-end demotions):

```
DEMOTE #13c4z4'_copied T op=1 ln=43 | [1:1004 #13c4z4'_copied @#0c2z0] <= [1:1004 #458c3z4]
```

The destination is still a kind-1 placeholder, so promotion had accepted the lowered store. The
demotion turns it back into memory. At 0x306c1 the IL is `#458 = #216; [copied] = #458`. The copy
from `#216` is a register move whose destination is not a source of `#216`'s definition, so phase 1
excludes `#216`.

## 3. Why a plain copy never reaches that state (globopt schedule)

`globopt_run` 0x107130cb ends like this [read]:

1. phase-3 CSE with jump threading (`cse_block`);
2. `rebuild_flow_graph` if dirty (0x107136e4);
3. **`globopt_dead_code_elim` 0x10713683**, the last dead-code pass;
4. `rebuild_flow_graph` if that pass left the flow graph dirty (**0x107136f2**);
5. a further dead-code pass only when `g_need_extra_dce` is set (0x1071370d). Outside the phase-1
   bracket in `globopt_run` (0x107134ac/0x107134b9), only 0x1070b474 sets it, while it expands IL
   ops 0x1ab/0x1ac;
6. `globopt_restore_temp_destinations`, `globopt_fold_adjacent_copies` and
   `globopt_finalize_tuples`. None of them removes a read of a local.

So a local definition that is dead at `build_live_ranges` must have lost its last read at step 4,
or in a later pass. After globopt, `pass_select_address_modes` only folds address constants
(`X = &global + k`), so it cannot drop a read of an `entry + 12` pointer. Step 4 removes the
compare of a branch whose target became empty in step 3. The witness guard
`if (copied != selected && entry->count <= 0) return;` is that shape: jump threading folds the
count test, and the pointer compare dies at 0x107136f2.

A plain `X = p`, `X = &entry->template_id`, a same-size union view, or an address-taken holder does
not survive to step 4. CSE rewrites the compare's read of X (copy propagation, or equal value
numbers that fold `X != p`). X's definition is then dead at an earlier dead-code pass and deleted.
Only a copy that CSE cannot forward keeps the read alive until 0x107136f2. The copy intrinsic 0x190
is such a copy, from `convert_loop_stores_to_block_op` 0x10747ed0 or from a `memcpy` whose size is
not a literal.

The alias-class route in [unfolded-field-pointers.md](unfolded-field-pointers.md) is not the
mechanism here. The function has 0x38 alias classes. With 500 code-free inline calls it has 0x406,
and `_trigger_cursor`, `_entry` and `_template_id` all collapse to class 1. That run has no store,
the pointer is still folded (`[esi+0x8]`, `[esi+0xc]`), and the score drops to 49.12%.

## 4. The compiler state that gives native

`scripts/c2/dead_def_intervene.py` runs at `build_live_ranges` entry. It finds the first
`NAME = temp` tuple and points every later read of NAME at the temp. NAME's definition is then dead
and goes through 0x107318e5 like X above.

| Run | Source | Result |
|---|---|---|
| canonical, no intervention | `entry->heading` | 91.23%, 113 insns, prefix 51 |
| h1, no intervention | `((float *)template_id)[-1]` | identical to canonical (NOTES: VC6 folds both spellings to the same code) |
| **h1 + dead def** | h1 | 86.09%, 115 insns, prefix 14. The `.text` (384 bytes) is **byte-identical** to the stock witness. The IL of h1 at `build_live_ranges` is `template_id = #216`, y = `[#216-8]`, heading = `[#216-4]`, and one read `[template_id]`. |
| **h1 + dead def + y base on entry** (`--rebase-lea=-8:_entry:4`) | h1 | 86.96%, 115/115 insns. The only diffs from native are the zero constant (`xor ebx,ebx` and `cmp …, ebx` in the scan, and the `ebx` clears in the group tail) and the branch labels after them |
| canonical + dead def | `entry->heading` | C2 crashes: the temp `#462` is block-local, and the rewrite makes it cross blocks |

So native needs, at `build_live_ranges`:

1. a 4-byte promoted local whose only definition in the group block is `X = p`, with no reads
   (the store and the `lea`);
2. heading addressed from p (`[p-4]`) but y from `entry` (`[entry+4]`). The canonical IL has both
   based on the y temp (`#229`). h1 has both based on p;
3. the constant-0 range coloured into `ebx` across the scan and the group loop. With the pointer
   range present, the queue is entry 190, spawn_index 116, p 88, … and zero −68 (canonical: zero
   −64 with no p). Zero loses `ebx` to `spawn_index` in the group block, as in the witness. The
   benefit of constant 0 is 3 in both runs. The earlier zero-splitting evidence found the needed
   change in the scan zero's cost.

Items 2 and 3 are the residuals already recorded in the scratch NOTES. Item 1 is the triplet.

### How heading and y bases arise (for item 2)

Merge #2 in the group loop is the same for canonical and h1 (`iv_merge_chain.py`: `#134` beats
`#92`, keeps against `#131`, then `#132`, the count field with 3 uses, wins). The bases differ only
in how `strength_reduce_address_operands` rebuilds the fields. In canonical it rebuilds on `#229`
(entry + 4); in h1 it rebuilds on the named pointer's temp `#216`. No source spelling tried gives
the mixed native form: position through `&entry->position`, through `quest_spawn_table[index]`, or
with heading read before the position.

## 5. Acceptance tests

Predictions were written before each compile. Refs are ok/unresolved/mismatch. Work dir:
`scratchpad/qst-dead-store/v/`.

| # | Variant | Prediction | Observed |
|---|---|---|---|
| 1 | g1: `int *checked = template_id; if (checked != 0 && entry->count <= 0) return;` | copy propagated, no store, canonical body | ✔ 91.23%, 113 insns, 13/0/0 |
| 2 | g2: same with `checked = &entry->template_id` | equal value number, no store | ✔ canonical body |
| 3 | u1: `union { int *pointer; unsigned bits; } copied` plus the guard on `bits` | **store** (the union view hides the copy) | ✘ canonical body. CSE forwards through same-size views of one location, so a union is not opaque. Rule refined: only 0x190 or volatile |
| 4 | u2: u1 with the guard operands reversed | no store | ✔ |
| 5 | m1: `memcpy(&copied, &template_id, n)` with `n` a variable, plus the guard | triplet | ✔ `lea edi,[esi+0xc]; mov [esp+0x10],edi; mov [esp+0x10],ebx` (82.61%, 115 insns) |
| 6 | m2: m1 with `entry->count <= 0` first | no store | ✔ no triplet (87.72%, 113 insns) |
| 7 | m4: the same copy of `float *heading_ptr = &entry->heading` | the stored value's range is kept: `lea edi,[esi+8]; mov [esp+0x10],edi`, fields rebased on it | ✔ `lea edi,[esi+0x8]`, template `[edi+4]`, y `[edi-4]` |
| 8 | m3: the same copy of `entry` itself | `mov [esp+0x10],esi`, no `lea` | ✘ `&entry` makes `entry` address-taken, and the allocation changes (48.70%, 5/0/1) |
| 9 | alias collapse, N = 500 code-free inline calls | pointer kept by class 1, no store | half: no store ✔, but the pointer is still folded ✘ (49.12%) |
| 10 | h1 + dead-def intervention | the triplet appears | ✔, byte-identical to the witness (observed, not predicted) |
| 11 | #10 plus y base on `entry` | only the zero-constant differences remain | ✔ 86.96%, the zero diffs only |
| 12 | corpus demotion scan | no second instance of a dead named-scalar store | ✔ 0 of 1244 scratches |

Negative control for the tools: canonical without intervention gives no `_template_id` or
`_copied` demotion (const_trace).

## 6. Predicting from source

- A stack store of a register value that is overwritten before any read comes from
  `demote_unused_candidate_def`. The definition was live through globopt's last dead-code pass and
  dead at `build_live_ranges`.
- If the stored register also holds a pointer used as an address later, that pointer is kept by the
  phase-1 value-use rule.
- Look for a copy the optimizer cannot forward (a byte loop or a variable-size `memcpy` into a
  local), whose last reader is a compare that jump threading makes pointless.
- The dead slot joins the next object defined after it, when that object is not live at the store.

## 7. Tools

```sh
uv run python scripts/c2/dead_def_intervene.py <scratch> --out <new-dir> [--name _template_id] [--rebase-lea=-8:_entry:4]
uv run python scripts/c2/demotion_scan.py --out <new-dir> [--jobs 8] [scratch-name ...]
```

- `dead_def_intervene.py` extends `const_trace.py`. It prints the rewrite, the named-local
  demotions, and the observed object's score and diff. It is diagnostic only; the whole COFF
  changes.
- `demotion_scan.py` runs `const_trace.py` on copies of the scratches and lists the demoted
  definitions of whole named locals.

## 8. Open questions

- Which pass in `build_live_ranges` or colouring makes a block-local temp crash when it is read
  across blocks (the canonical intervention)?
- What source rebuilds heading on the template pointer but y on `entry`? The rebuild in
  `strength_reduce_address_operands` 0x10748429 was observed, not decoded.
- What IL gives the constant 0 the `ebx` colour with the pointer range present? It is the same
  question as the zero-splitting evidence (scan-zero cost), now with the pointer kept by the dead
  store instead of by an intervention at 0x309bb.
- 0x1070b474 is named `lower_copy_intrinsics`, but it only expands IL ops 0x1ab/0x1ac into
  assignments. Which source construct emits those ops was not tested.
