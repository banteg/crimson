# Timeline sources for the 1.9.8 body and the 8966 dead store

`quest_spawn_timeline_update` stays at **91.228070%** (113/115 instructions, 13/0/0 references). This
note changes no scratch source or compiler setting. It adds three results:

1. Plain C++ spellings of the spawn group reproduce the **1.9.8 body exactly** under the Processor Pack
   C2 (`msvc6.5pp`, build 9044). The earlier [history controls](../quest-history-controls-2026-09-28/README.md)
   did not reproduce 1.9.8 from the current scratch.
2. Some of these sources compile under C2 8966 to native's +0 anchor with dead pointer stores that 9044
   drops. A single source can therefore produce both historical bodies in anchor, zero handling and
   dead stores. This does not yet give the native triplet.
3. The route by which C2 8966 leaves a dead named-pointer store without an opaque copy. It also explains
   why that route cannot store native's `esi + 0xc` in these source families.

## Sources

The four files in [sources/](sources/) differ from the canonical scratch only after `spawn_entries:`.
[compare.py](compare.py) builds each file with both compilers and compares it with the address-masked
historical bodies that [historical.py](../quest-history-controls-2026-09-28/historical.py) extracts.
The results are in `results.json`:

| Source | 9044 vs 1.9.8 | 8966 vs 1.9.93 | 8966 pointer stores |
|---|---|---|---|
| canonical scratch | 77.88% | 91.23%, 113 insns | none |
| `top_entry_indexed_template` | **exact** | 77.19%, 113 | none |
| `indexed_loop_template_pointer` | **exact** | 73.04%, 115 | `[esp+0x14], esi` |
| `top_entry_indexed_x` | **exact** | 71.86%, 116 | `[esp+0x14], esi` twice |
| `block_entry_dead_store` | 77.88% | 87.72%, 113 | `[esp+0x10], esi` before `spread = 0` |

The 1.9.8 spellings share the following shape:

- The entry pointer is re-derived from `entry_index` inside the group loop, or there is no entry
  pointer at all.
- At least one spawn-loop field is read through `quest_spawn_table[entry_index]`.

Then every field pointer is a derived induction variable of `entry_index`. Merge #2 keeps the
count field, which gives 1.9.8's `[esi-0x14]` addressing. `indexed_loop_template_pointer` is fully
indexed, the style that `quest_start_selected` and `ui_render_hud` use for this table. Its pointer is
declared inside the spawn loop and the heading is read as `((float *)template_id)[-1]`.

The canonical cursor source does not produce 1.9.8 under 9044 for any of 43 flag controls, including
/Ox, /Oa, /Ow, /G6, /Ob2, /GX, /Oy- and /Op. For that source, 8966 and 9044 differ only in the
float-compare lowering (`test ah, 1; jne` versus `test ah, 5; jnp`).

## One source, two bodies

`top_entry_indexed_x` compiles exactly to 1.9.8 under 9044. Under 8966 it keeps native's +0 anchor
(`[esi+0x14]`) and native's shared zero in `ebx`. It also stores the IV twice to `[esp+0x14]`. Those
stores are remnants of the class-3 address temp for the indexed x reads, whose definitions strength
reduction turned into copies of the IV. 9044 compiles the same source without them and anchors on the
count field.

In the index-family grid below, 32 of the 1.9.8-exact sources keep the +0 anchor under 8966. So the
1.9.8 differences in anchor, zero materialisation and dead stores are compiler-sensitive for these
spellings. A same-source explanation for 1.9.1/1.9.93 versus 1.9.8 remains possible. It is not
established.

## How a dead named-pointer store survives in 8966

Traced with [globopt_tail_trace.py](globopt_tail_trace.py). It adds dumps around the steps after the
loop optimizer and prints the `+0x32` flag of class-3 symbols.

1. **CSE copy propagation only forwards flagged temps.** `find_available_copy_source` 0x10709b5a
   replaces a use of a named local by its copy source `y` (a class-3 temp) only in two cases:
   - `y` has symbol flag `+0x32 & 3`, set by `get_derived_iv` 0x10753def on derived IVs and by the
     countdown counter 0x1074ce51;
   - the use is a compare that already contains `y`.

   Merge #2 rewrites a losing IV's uses through 0x10754627 → 0x1070afeb with fresh unflagged temps.
   `strength_reduce_address_operands` rebuilds on unflagged front-end temps. After the loop optimizer,
   only the surviving champion IV is flagged.
2. **One DCE pass, precomputed block liveness.** The last `globopt_dead_code_elim` (call 0x10713683)
   walks backwards once, using the live sets allocated just before it (0x1070789c). Suppose a
   definition's only remaining reads are loads in other blocks that CSE has made redundant. The pass
   deletes those loads and keeps the definition. `build_live_ranges` then demotes the definition to a
   store through 0x107318e5.
3. **Example.** In `block_entry_dead_store`, `entry = #328` copies the flagged +0 champion.
   - Phase-3 CSE rewrites the first `entry->position.x` load onto `#328` and makes the other two dead.
   - The definition of `entry` survives, and 8966 emits `mov [esp+0x10], esi` immediately before
     `spread = 0`. This is native's position and slot.
   - Unlike native, the x loads stay merged on the x87 stack (`fcom`, `fcomp st(1)`).
   - The `template_id = #501` copy is unflagged. Its read is never redirected, and forward
     substitution later folds it into `[esi+0xc]`.

Native stores `esi + 0xc` while its IV anchor is +0. Under rule 1, a store made this way can only hold
the champion's own value. The trace also shows why this family cannot reach
[qst-dead-store.md](../../c2/compiler/qst-dead-store.md) §4. Its intervention needs a cross-block
`entry + 12` temp. Only the canonical cursor source makes one: the shared rebuild temp `#216`. In the
index family, merge gives each use its own block-local temp, and the intervention crashes C2. The
missing native piece is therefore still a source-level way to make the canonical `template_id` reads
disappear after the last dead-code pass.

## Index-family grid

[grid.py](grid.py) generates 2,846 distinct spawn-group spellings. It varies:

- entry at the group top, in the block, or absent;
- no template pointer, one from the index, or one from entry, declared at the group top, in the block
  or in the spawn loop;
- heading through entry, the index or the pointer;
- x through entry, the index or a float local;
- entry or index for y, loop count, guard, zeroing and the trigger pair.

Results:

- 492 are exact against 1.9.8 under 9044. Of these, 32 keep the +0 anchor under 8966.
- None is exact against 1.9.93.
- None produces a `lea r, [esi+0xc]` under 8966.

Earlier unpackaged sweeps (1,056 per-site mixes including a `++entry` cursor; 818 block-local
template-pointer mixes) agree: 415 were 1.9.8-exact, and none had the native pointer.

## Reproduce

```sh
uv run python tools/match/evidence/quest-history-controls-2026-09-28/historical.py --out /tmp/quest-history
uv run python tools/match/evidence/quest-history-sources-2026-09-28/compare.py \
  --history /tmp/quest-history --out /tmp/quest-history-sources
uv run python tools/match/evidence/quest-history-sources-2026-09-28/grid.py \
  --history /tmp/quest-history --out /tmp/quest-history-grid --jobs 8
uv run python tools/match/evidence/quest-history-sources-2026-09-28/globopt_tail_trace.py \
  <scratch-dir-with-block_entry_dead_store> --out /tmp/quest-tail-trace --grep "'_entry\]" "'_template_id"
```

`compare.py` asserts the table's exact rows and store patterns. The grid takes about 20 minutes with
8 jobs.
