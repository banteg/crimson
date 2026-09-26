# Invisible live ranges: what P counts, and what disappears before and after it is counted

C2.DLL 12.00.8966 (image base 0x10700000), `/O2 /G5`. The global colourer charges every range with
P, the number of candidate live ranges referenced in a block ([regalloc.md](regalloc.md) §3.5,
[guard-placement.md](guard-placement.md) §2). This note answers three questions:

1. Exactly which references count toward P.
2. Which IL constructs are counted in P but emit no instruction (an *invisible range*), and which
   ones are deleted before P is computed.
3. Can the snail-mail Dip function (`initialize_dip_path_template_pair`) get the one extra block-1
   range that guard-placement.md asks for?

Evidence labels: **Verified** means observed in a compile trace (the new
`scripts/c2/block_refs_trace.py`, `scripts/c2/priority_trace.py`, `il_stage_trace.py`) or in matcher
output. **Read** means read from the disassembly. **Inferred** means neither.

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
priority deltas in every Dip block checked (block 1: 13, block 2: 2, block 4: 9, block 5: 6,
block 7: 5, block 18: 8, block 19: 11, block 23: 5).

**Correction.** `block+0x48` is not P. It holds the ranges referenced *or live* in the block, of every
class. In Dip block 5 it has 11 members while P is 6. The two agree in Dip block 1, where nothing is
live-through. guard-placement.md §"Open questions" and its follow-up comment at
0x10724c6d assumed they were equal.

### Which scoring run counts

P is recomputed in every run of `score_live_ranges`: the initial scoring (score0, call site
0x1072fc30) and every rescoring after a split (0x1072fd62). `prune_low_use_live_ranges` 0x10725b42
runs right after score0 and removes ranges for good. **A range pruned there counts in score0 only.**
Split pieces are always rescored, so a piece's priority depends only on the ranges still alive when it is
rescored.

Verified: in Dip, block 23 (the mesh preheader) has P = 5 at score0 (constants 1 and 2, the
`&g_texture_refs` address, and the reloads of `texture_a` and `texture_b`). All five are pruned, and at
every rescoring block 23 has no candidate tuples left, so P = 0. The zero piece that decides the Dip
colouring is scored in the second rescoring (guard-placement.md §2), so ranges pruned after score0 do
not help it.

## 2. Deletion timeline

| Pass | What it deletes or merges | Counted in P? |
|---|---|---|
| global optimizer (copy propagation, DCE, forward propagation of single-use expressions, IV cleanup) | plain copies, single-use pointer locals, `forceinline` pointer parameters, dead user inits of IVs that merge #1 rewrote | no, gone before RA. Verified: `p1`..`p8` below keep P |
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

[Verified for Dip block 1 with `block_refs_trace.py`: 18 candidate ranges at colouring entry. The
coalescer removes `#1812 = endpoint` (17). Forward substitution removes the four `lea this+disp`
temporaries #1190, #1198, #1208, #1228 (13). The x87 fold changes nothing in the integer class
(13). The pressure pass folds `#1807 = #1808` and `endpoint = #1802` into their ranges (13). At
score0 P = 13.]

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
survives. [Verified: the Dip latch `i = #1294`, where #1294 = `i + 1` is defined mid-body.] Both
ranges are still counted in the latch block. The chooser's copy preference then gives them one
register, so the final code has no `mov`: ours `inc ebp; mov [esp+0x20], ebp`, native
`inc ebx; mov [esp+0x20], ebx`.

## 3. Invisible ranges: the classes

| # | Construct | Counted | Deleted by | Final code | Example (Dip, verified) |
|---|---|---|---|---|---|
| a | LOADCONST (0x163 with an immediate source) of a constant with ≥ 2 eligible uses that ends uncoloured | score0 and every rescoring (constants with benefit ≤ 0 are deferred, not pruned) | demotion near the end, then 0x107395e3 | immediates | block 1: `0.49f` (two stores) and `168` (load placed at the end of block 1, uses in blocks 2, 4, 7, 11, 21) |
| b | reload of a memory candidate (parameter or spilled local) with one use in another block | score0 only | prune: the 2-ref reload is folded into its use; the /G5 split 0x107337ec may put a `mov reg,[mem]` back | same as a direct memory operand | block 23: `texture_a`, `texture_b` (`mov eax,[esp+0x78]; push eax`) |
| c | copy into a multi-definition range from an earlier single-definition range (coalescer rule A/B fails), both ranges given one register | every run | `mov r, r` dropped after rewrite | nothing | block 7: `i = #1294` |
| d | a candidate that survives build_live_ranges, then has benefit ≤ 0 and is demoted late, where the memory form is the code a non-candidate would give | every run until demoted | `demote_live_range` 0x10725eed | memory operands, or stores to the home | block 4: `#1066`, the integer view of `angle` pushed for `Cos`, alive in every rescoring |

The constructs the snail question listed map onto this as follows:

| Construct | Verdict |
|---|---|
| Coalesced copy | Not counted: 0x10730308 runs before scoring. Only a copy the coalescer refuses (class c) counts. |
| Second web of a parameter | A web used once inside one block becomes a local temp in `build_live_ranges` (`width_cells_` → #1477). Not counted. |
| Constant used twice with benefit ≤ 0 | Counted, class a. It is deferred, not pruned, so it still counts in rescorings. |
| Multi-use CSE temp whose uses all fold into addressing | Not counted when it is a single-def `lea`: forward substitution folds it before scoring (#1208 = `&this->primary_samples`). |
| Dead store eliminated late | No such pass for candidates. Dead candidate defs die in `build_live_ranges` (not counted). Dead memory stores are never deleted after globopt ([post-promotion-stores.md](post-promotion-stores.md) §3.1). |
| REGUSE / physical-register operands | Never counted: their home is not a live range. |
| Parameter re-read | A parameter read in two blocks is a candidate and counts (class b if it has one use: score0 only). |

Where a constant's LOADCONST goes [Verified placements, rule Inferred]: it is placed right before
the first use when that use is in the block that dominates all uses (0, 1.0f, 0.49f in Dip block 1).
Otherwise it goes at the end of the nearest block that dominates all uses (168: end of block 1; 1, 2
and `&g_texture_refs`: the mesh preheader, block 23). A new constant therefore lands in block 1 only
if its uses start there or span both the curve region and the code after it.

## 4. Dip (`initialize_dip_path_template_pair`)

Source: snail's `tied_guarded` (= `sm/dip4/late.cpp`: `int i = 0; if (…) { int sample_offset =
sizeof; do … while }`), 86.18%. The zero piece is 133 against the `vertices` piece's 144, and
+12 on the zero piece gives native (guard-placement.md §2).

### Block 1 at the rescoring that decides the zero piece (run 2) [Verified]

P = 13: `this`, 1.0f, **0.49f**, `curve_count` #9, `endpoint` webs 1 and 2, `i` #14, zero piece,
**168 piece**, and the temporaries #1197 (`endpoint + 1`), #1210 (`primary_samples` CSE), #1238
(`primary + endpoint`) and #1807/#1808 (`endpoint * 7`). `tied_single` has the same set plus `sample_offset` #15 (P = 14).

The snail list of 12 left out 168. Two of the 13 are already invisible (class a: 0.49f and 168).

### Why block 1 cannot supply a fourteenth range with native's instructions

Native's block 1 is identical to ours instruction for instruction (the +12 intervention is 655/655
normalized), so the new range must be invisible and must still be alive at run 2.

- **Class a** needs a new constant value with two eligible uses whose load lands in block 1. Native's
  function has none spare. Block 1's eligible immediates are 0x14 (a single use, turned back before
  scoring), byte and dword 0, 1.0f, 0.49f and 168, which are all already counted. `+1` is `inc` and
  `-1` is `dec` before promotion (0x21/0x1e at `build_live_ranges` entry). Every other immediate in the
  function is an address displacement (`lea`), a shift count (refused), a store that is still an
  unpromoted immediate at scoring (the `Vector3(1,0,0)` temporaries in the loop), or a mesh-only
  constant whose load sits in block 23.
- **Class b** is pruned after score0, so it cannot move the run-2 zero piece. Native also has no
  later memory read that could be such a use.
- **Class c** needs a multi-definition range in block 1 fed by a copy from a separate single-def
  range that dies there. Block 1 has only `i` (initialised from constant 0, and constant sources are
  never recorded) and the two-operand results of `endpoint *= 168`. Their sources are lowering temps
  (#1808, #1802) that the pressure pass folds. Turning one into a candidate needs a second use, and
  that use is visible.
- **Class d**: the only memory-only local in block 1, `endpoint_index`, is demoted inside
  `build_live_ranges`, because its register value is dead at block end (its only use, `fild`, reads
  memory). A `(float)i` reuse of `i` behaves the same (`s4`). Keeping it alive needs a register use or
  a later `fild`, and both are visible.

Compiled on copies of the guarded form. Every row keeps P(block 1) = 13 in score0 and run 2 unless
noted:

| Variant | Change | Result |
|---|---|---|
| e1 | `endpoint = endpoint_index * sizeof` | 86.18%, identical (copy propagated) |
| e2 | `endpoint_index` from `curve_count + 1`, new `endpoint = endpoint_index * sizeof` | 85.87% |
| z1, z2 | `endpoint_z` from `(float)(curve_count + 1)` / before the multiply | 85.50%, 84.05% |
| z3 | `(float)(endpoint / sizeof)` (control, a visible divide) | **P 14, zero 146, ebp**, but 90.05% (+7 instructions) |
| x_idx | endpoint stores in index form `primary_samples[endpoint]` | 85.50% |
| p1..p8 | pointer local, `identity_at(bank, offset)`, `identity_sample(ptr)` helpers for the endpoint and sample-0 `Identity` calls | 86.18%, identical (propagated) |
| r1..r4 | Dump-style `PathAttachmentSample* const& bank = …` bindings | 85.78–86.18% |
| s1..s4 | `sample_index` / reuse of `i` for the endpoint z (Hump departure style) | 86.18%, 83.96% (s4) |
| w1..w5 | `width_cells_` and `curve_count` roles swapped or mixed | 83.72–86.18% |
| k3, k6, k7 | cursor also initialised before the `if`, SR cursor inside the `if`, `while (++i < …)` | 85.80–86.18% |
| i2, i3, i4 | `++i` moved (zero 135 in i2: a loop-block effect) | 85.71%, 69.49% |
| h1, m_dump, m_hump | Hump's `compute_terminal_deltas`; Dump's and Hump's `build_strip_mesh` | 86.18%, unchanged priorities |
| live_i | live scratch with `int curve_phase_index = i;` | 99.85%, same as `= 0` (constant propagated) |

### Where +12 can still come from

The zero piece's run-2 budget is block 1 +169 (P 13 × S 13), block 4 +72 (P 9 × w 2 × S 4), and
live-through charges of −108 over blocks 2, 5, 6, 7, 11, 17, 18, 20, 21, 25 and 40 (block 18 alone
is −32 = P 8 × w 4). The `vertices` piece gets +64 in block 18 (S 2) and +88 in block 19
(P 11 × w 4 × S 2), and pays small charges elsewhere. From these numbers [Inferred, not
source-tested]:

- One more range still alive at run 2 in the loop head (block 4) is worth +8. Two are needed.
- One range fewer in vertex-loop block 18 gives zero +4 and `vertices` −8. That is 137 against 136,
  and zero is coloured first.
- One range fewer in block 19 gives `vertices` −8 and leaves zero unchanged.
- One more zero **store** in block 1 is +13 via S. This is the live scratch's
  `curve_phase_index = 0`, 148. It is visible as `mov [esp+0x14], ebp`, where native has ebx.

## 5. Tool

```sh
# Crimson scratch
uv run python scripts/c2/block_refs_trace.py <scratch> --out <new-dir> --block 1 [--block 7] [--rescore] [--il]
# snail-mail scratch (run from the snail-mail checkout)
uv run python ../crimson/scripts/c2/block_refs_trace.py --snail <scratch> --out <new-dir> --block 1 --rescore
uv run python scripts/c2/block_refs_trace.py --reuse <trace-dir> --block 4
```

For every register-allocation stage (`blr`, `colour`, `coalesced`, `substituted`, `x87`, `score0`,
each `rescore`, `local`) it prints the candidate live ranges each selected block references, which is
P at `score0` and at each `rescore`, and the tuples removed since the previous stage. Use it with
`priority_trace.py`, which gives the per-block priority contributions.

## Open questions

- Which native Dip source gives +12. The block-1 route is closed for the constructs above. The
  remaining candidates are loop-head (block 4) and mesh (blocks 18/19) reference sets, with identical
  instructions. The search criterion is the run-2 zero piece against the `vertices` piece in
  `priority_trace.py`, not P(block 1).
- The exact placement function for constant loads (the join step 0x1072e5b9 was not decoded). The
  rule above is from observed placements.
- The 14 SIB swaps in the curve loop (guard-placement.md §4) are still open. Every variant here keeps
  our register-plus-register order.
