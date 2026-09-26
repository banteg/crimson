# Invisible live ranges: what P counts, and what disappears before and after it is counted

C2.DLL 12.00.8966 (image base 0x10700000), `/O2 /G5`. The global colourer charges every range with
P, the number of candidate live ranges referenced in a block ([regalloc.md](regalloc.md) §3.5,
[guard-placement.md](guard-placement.md) §2). This note answers two questions:

1. Exactly which references count toward P.
2. Which IL constructs are counted in P but emit no instruction (an *invisible range*), and which
   ones are deleted before P is computed.

Evidence labels: **Verified** means observed in a compile trace (`scripts/c2/block_refs_trace.py`,
`scripts/c2/priority_trace.py`, `il_stage_trace.py`) or in matcher output. **Read** means read from the
disassembly. **Inferred** means neither. The traces were taken on Snail Mail's
initialize_dip_path_template_pair.

## 1. What P counts

`score_live_ranges` 0x10724b25 walks the blocks. For each block it walks the real tuples (flag bit 1)
forward and looks at every kind-1 source and destination operand whose **operand type** belongs to
the class being scored (`g_type_class` 0x107a09bc; integer type nibbles 1, 2, 3, 5, 7, x87 nibble 4).
The operand's home is `op+0x18`, and the record at `home+8` decides what is counted [Read,
0x10725256..0x10725312 for sources, 0x10725331.. for destinations]:

| Home | Counted in | Set at |
|---|---|---|
| kind ≠ 2: a physical register descriptor (`this` in ecx at entry, the `ftol` result in eax, thiscall `ecx` copies) | not counted | |
| live range, already coloured (`+0x10` ≠ 0) | the "def list": linked once per block, flags6 bit 8 | 0x10724cec, 0x10724f44 |
| live range with flags5 bit 0x01 clear (inferred: not in the set being scored) | `bs_1`, a bitset of range ids | 0x10724e42, 0x1072519a |
| live range in the set being scored | the live list, flags6 bit 0x10 | 0x1072530f, 0x10725112 |

At the end of the block, `P = popcount(bs_1) + |def list| + |live-list entries with flags6 & 0x10|`
(0x10724c3b..0x10724c6b). So **P is the number of distinct candidate live ranges that any real tuple
of the block references with an operand of the scored class**. Address components count, because the
base and index of a kind-5/6 memory operand are also listed as separate kind-1 sources. A LOADCONST or
reload (0x163) counts: its destination path (0x10724f0b..0x10724f3f) charges the load and sets the
referenced flag, but adds nothing to S. A spill store (0x164) counts too (0x10724d72..0x10724da4, then
0x10725304), again with no S.

Verified: the P computed from the IL at `score_live_ranges` entry equals the one implied by the
priority deltas in every block checked.

**Correction.** `block+0x48` is not P. It holds the ranges referenced *or live* in the block, of every
class. The two agree only in a block where nothing is live-through. The Binary Ninja comment at
0x10724c6d carries this correction.

### Which scoring run counts

P is recomputed in every run of `score_live_ranges`: the initial scoring (score0, call site
0x1072fc30) and every rescoring after a split (0x1072fd62). `prune_low_use_live_ranges` 0x10725b42
runs right after score0 and removes ranges for good. **A range pruned there counts in score0 only.**
Split pieces are always rescored, so a piece's priority depends only on the ranges still alive when it is
rescored. Ranges pruned after score0 do not help a split piece.

Verified: a block whose only candidates were two constants, an address constant and two parameter
reloads had P = 5 at score0. All five were pruned, and at every rescoring the block had no candidate
tuples left, so P = 0.

## 2. Deletion timeline

| Pass | What it deletes or merges | Counted in P? |
|---|---|---|
| global optimizer (copy propagation, DCE, forward propagation of single-use expressions, IV cleanup) | plain copies, single-use pointer locals, `forceinline` pointer parameters, dead user inits of IVs that merge #1 rewrote | no, gone before RA [verified] |
| `build_live_ranges` 0x10726d75 | single-use constants turned back into immediates; a parameter web read once inside one block turned into a class-3 local temp; webs whose register value is never read (memory-only uses such as `fild`) demoted by `demote_unused_candidate_def` 0x107318e5 at block end | no |
| `coalesce_copy_live_ranges` 0x10730308 | `mov lrA, lrB` (rules below); the copy and one range | no |
| `forward_substitute_single_def_ranges` 0x107306c1 | single-def `lea`/address ranges folded back into addressing | no |
| `fold_x87_copy_sequences` 0x1072fef2 | x87 copies (class 1) | no (integer P unchanged) |
| `mark_register_pressure_splits` 0x10730ab7 | copies from a class-3 **local** temp into a candidate: the temp joins the range | no |
| **score0** | | P is fixed for the initial priorities |
| `prune_low_use_live_ranges` 0x10725b42 | ranges with < 2 refs are demoted; a 2-ref reload is folded into its use | counted in score0 only |
| colouring loop | ranges with benefit ≤ 0 are deferred and demoted on the second visit, near the end | counted in every rescoring until then |
| chooser preference, then `rewrite_live_range_operands` 0x107388f3 | a copy whose two ranges got one register becomes `mov r, r` and is dropped (the dropping pass was not isolated) | counted in every run |
| after colouring | constant registers with `const_score` ≤ 2 back to immediates (0x107395e3); `late_register_value_cse` deletes loads only; `late_stack_temp_forwarding` deletes class-3 temp pairs only | counted in every run |

`block_refs_trace.py` shows each step for one block: the coalescer, forward substitution of `lea this+disp`
temporaries and the pressure pass each remove ranges between colouring entry and score0 [verified].

### The coalescer's two rules (0x10730308)

[Read.] The first walk counts definitions per range in `lr+0x24` and records every real `mov` whose
single destination and single source are live ranges and whose source is not a constant (class
0x0d). Each recorded copy is then merged by one of two rules, or not at all:

- **A** (0x10730622): the destination range has exactly one definition. It is merged into the source,
  unless `has_intervening_base_definition` fails or the destination type is wider.
- **B** (0x10730631..0x10730668): the destination has several definitions, the source has exactly one,
  and that definition is the **immediately preceding real tuple** (not a reload), with the same type.
  The definition is renamed to write the destination directly.

A copy into a loop-carried variable (several definitions) from a value defined earlier therefore
survives. [Verified: a loop latch `i = t` where `t = i + 1` is defined mid-body.] Both ranges are still
counted in the latch block. The chooser's copy preference then gives them one register, so the final code
has no `mov`: `inc r; mov [mem], r`.

## 3. Invisible ranges: the classes

| # | Construct | Counted | Deleted by | Final code |
|---|---|---|---|---|
| a | LOADCONST (0x163 with an immediate source) of a constant with ≥ 2 eligible uses that ends uncoloured | score0 and every rescoring (constants with benefit ≤ 0 are deferred, not pruned) | demotion near the end, then 0x107395e3 | immediates |
| b | reload of a memory candidate (parameter or spilled local) with one use in another block | score0 only | prune: the 2-ref reload is folded into its use; the /G5 split 0x107337ec may put a `mov reg,[mem]` back | same as a direct memory operand |
| c | copy into a multi-definition range from an earlier single-definition range (coalescer rule A/B fails), both ranges given one register | every run | `mov r, r` dropped after rewrite | nothing |
| d | a candidate that survives build_live_ranges, then has benefit ≤ 0 and is demoted late, where the memory form is the code a non-candidate would give | every run until demoted | `demote_live_range` 0x10725eed | memory operands, or stores to the home |

Common candidate constructs map onto this as follows:

| Construct | Verdict |
|---|---|
| Coalesced copy | Not counted: 0x10730308 runs before scoring. Only a copy the coalescer refuses (class c) counts. |
| Second web of a parameter | A web used once inside one block becomes a local temp in `build_live_ranges`. Not counted. |
| Constant used twice with benefit ≤ 0 | Counted, class a. It is deferred, not pruned, so it still counts in rescorings. |
| Multi-use CSE temp whose uses all fold into addressing | Not counted when it is a single-def `lea`: forward substitution folds it before scoring. |
| Dead store eliminated late | No such pass for candidates. Dead candidate defs die in `build_live_ranges` (not counted). Dead memory stores are never deleted after globopt ([post-promotion-stores.md](post-promotion-stores.md) §3.1). |
| REGUSE / physical-register operands | Never counted: their home is not a live range. |
| Parameter re-read | A parameter read in two blocks is a candidate and counts (class b if it has one use: score0 only). |
| A value only read as memory (`fild`) | Demoted inside `build_live_ranges` because its register value is dead at block end. Not counted. |

`+1` and `-1` are `inc` and `dec` before promotion, so they never become constant candidates.

Where a constant's LOADCONST goes [Verified placements, rule Inferred]: it is placed right before
the first use when that use is in the block that dominates all uses. Otherwise it goes at the end of the
nearest block that dominates all uses. A new constant therefore lands in the entry block only if its uses
start there or span both a loop and the code after it.

## 4. Tool

```sh
uv run python scripts/c2/block_refs_trace.py <scratch> --out <new-dir> --block 1 [--block 7] [--rescore] [--il]
uv run python scripts/c2/block_refs_trace.py --reuse <trace-dir> --block 4
```

For every register-allocation stage (`blr`, `colour`, `coalesced`, `substituted`, `x87`, `score0`,
each `rescore`, `local`) it prints the candidate live ranges each selected block references, which is
P at `score0` and at each `rescore`, and the tuples removed since the previous stage. Use it with
`priority_trace.py`, which gives the per-block priority contributions.

## Open questions

- The exact placement function for constant loads (the join step 0x1072e5b9 was not decoded). The
  rule above is from observed placements.
