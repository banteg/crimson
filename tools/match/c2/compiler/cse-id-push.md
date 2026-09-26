# CSE id push: can authored code move a bank temporary past 0x800? (C2.DLL 8966)

TurnoverDouble and HalfPipe (snail-mail path builders) each keep one `+0x90` SIB swap. At the swap site the bank
is a CSE symbol leaf, ranked by `(id << 6) & 0xffff` ([cse-slot-count.md](cse-slot-count.md),
[sib-operand-order.md](sib-operand-order.md)). Native puts the offset local first, so the bank's `id mod 1024`
has to fall in a small window just past a multiple of 1024. This note measures that window and the id cost of
the natural source constructs. It then asks whether any of them reaches it with the code unchanged.

The short answer is no. The shift has to be about 6 to 26 blocks of 32 ids. Measured code-identical constructs
move C0 by 0 to +7 blocks and n by 0 or +1.

"Verified" means a compile checked by the snail matcher. "Intervention" means a phantom run, which burns extra
pool-E ids in a traced compile (`cse_slot_trace.py --phantom`, or the new `cse_id_window.py`). "Inferred" means
it fits the data but was not traced.

## 1. What an id is made of

`id = C0 + n`:

- **C0** is the symbol-id counter `g_next_symbol_id` 0x1079bc4c when the first CSE slot is allocated. Every pool
  takes 32-id chunks from the same counter (`symbol_chunk_new` 0x107079c3). So C0 = 32 × (chunks opened before
  value numbering), and it moves only in whole blocks.
  - `symbol_pools_reset` 0x1071b9b0 sets the counter to 0 and opens the first chunk of pools B, C, A and D
    [read].
  - `cse_id_window.py --chunks` lists the chunk openers. In TurnoverDouble 37 chunks come before C0 = 0x4a0:
    - 29 are opened while the IL is read: `reader_binary_op` / `tuple_new_binary_temp` 14, `reader_read_call` 4,
      `node_alloc` 3, parts 4, `fe_symbol_get_storage` 1, compare 1;
    - 6 are opened later, by tree simplification (`emit_tree_as_tuples` 2, `fold_constant_operands` 1,
      `simplify_conversion` 3).
  - So C0 tracks the IL size of the **whole function**, including code after the swap site. Deleting regions
    of TurnoverDouble (code-changing probes) removes about 17 blocks for the mesh, 5 for the curve loop, 4 for
    the delta loop and 2 for the tail loop [verified].
- **n** is the bank slot's position in value numbering. Only tuples before it count, at the costs in
  [cse-slot-count.md](cse-slot-count.md).

Temporary hashes use `id mod 1024`. A C0 change of −k blocks therefore ranks every CSE temp exactly like a
+(32 − k)-block change. A `0:M` phantom (burn M ids before slot 0) reproduces that for all temps, but locals do
not move.

Pool-B chunks opened by locals and parts move C0 as well ([pu-id-delta-profile.md](pu-id-delta-profile.md)).

## 2. The windows (intervention)

`cse_id_window.py <scratch> --out <dir> 28:830..850 0:832..848 0:832,28:3..14 ...`:

### TurnoverDouble

C0 0x4a0, 735 slots. Bank `temp 0x4bc` = n28 (`id mod 1024` 188, hash 0x2f00), against local 0x13 (hash 0x260).
The swap is at +0x2b1.

| Phantom | Byte exact | Failures |
| --- | --- | --- |
| `28:M` | M = 836–841, 843–845 (bank 0x800–0x809) | 842: 95.23%; ≤835 or ≥847: swap (846 and 850: 95.23%) |
| `0:M` (whole function) | M = 836, 837, 840, 841, 844, 845 | M ≡ 2 (mod 4): 92.76%; M ≡ 3: 99.71% |
| `0:832,K:s`, K = 7, 22, 28 | s = 4, 5, 7, 8, 9, 11, 12, 13 | s = 3: swap; s ≡ 2 (mod 4): 93–95% |

The mod-4 failures are the two load-leaf rules from Hill/Valley:

- **The secondary bank address n50** (`this+0x5c`, id 0x4d2) must stay ≢ 0 (mod 4). `0:832,28:4,50:2` puts it at
  ≡ 0 and fails (95.23%). `0:832,28:6,50:2` and `28:6,50:1` are exact.
- **The width_cells address n6** (0x4a6) must stay ≡ 2 or 3. `0:832,6:3` gives 99.71%; `0:832,7:3` is not
  affected.

Rule: the bank's `id mod 1024` must be in 0–9, `n(this+0x5c) mod 4` ≠ 0, and `n(this+0x54) mod 4` ∈ {2, 3}.

### HalfPipe

C0 0x4a0. Bank `temp 0x4fc` = n92, the load through the `primary_bank` reference in the tail loop (`id mod 1024`
252, hash 0x3f00), against local 0x17 (0x2e0). The swap is at +0x2f9.

| Phantom | Byte exact | Failures |
| --- | --- | --- |
| `92:M` | M = 772–783 (bank 0x800–0x80b) | 768–771 and 784–790: swap; `93:772`: swap; `91:772`: exact |
| `0:M` | 772–783 except 774, 778, 782 | M ≡ 2: 93.94% |

The ≡ 2 failure is again the secondary address, n62 (0x4de): `0:768,92:4,62:2` and `92:6,62:2` give 94.57%,
while `0:768,63:6` is exact.

Rule: the bank's `id mod 1024` must be in 0–11, and n62 stays ≢ 0 (mod 4).

### What that means in blocks

| Function | Needed ΔC0 (blocks) + Δn before the bank |
| --- | --- |
| TurnoverDouble | +26 (≡ −6) with Δn 4–13, no Δn ≡ 2 before n50; or +27 (≡ −5) with Δn −28 to −19 |
| HalfPipe | +24 (≡ −8) with Δn 4–15; or +25 (≡ −7) with Δn −28 to −17 |

No pure C0 change works: neither window contains a multiple of 32. TurnoverDouble has only 28 slots before its
bank, so it cannot lose 19 of them. Snail's sibling bound says any family-wide IL difference is at most about four
blocks (address-order.md, "Sibling bound").

## 3. What natural constructs cost (verified: compile, trace, match)

TurnoverDouble. "Same" means 100% normalized with the original single swap.

| Construct | Code | ΔC0 | Δn |
| --- | --- | --- | --- |
| Inlined per-segment helper `initialize_straight_sample_pair(Path*, int offset, int index)` for lead and tail (lead body) | same | 0 | 0 |
| The same helper with the tail body | 95.88% | 0 | 0 |
| `compute_terminal_deltas` / `build_strip_mesh` written in the body instead of as helpers | same | 0 | 0 |
| Hill/Valley's `build_strip_mesh` | same | +1 | 0 |
| its component-constructor `generated_position` alone | same | +1 | 0 |
| its `face_index + 2 * (row * w + column)` / `(column & 1) == (row & 1)` forms | same | 0 | 0 |
| Turnover's logical-index delta helper | 10 new swaps | +1 | 0 |
| `(unsigned int)` instead of `(char *)` byte casts: everywhere / body / helpers | same | +7 / +5 / +2 | 0 |
| `PathTemplateSample *` casts, or `(*(T *)…).f` instead of `((T *)…)->f` | same | 0 | 0 |
| header: `int total_segments` local (either position), `int zero` for the zero stores | same | 0 | 0 |
| header: `segment_count_f = (float)segment_count` | same | 0 | +1 |
| header: reordered `width_or_scale`, `length = (float)curve_segments * k`, hoisted `lead_center_x` | 99.41 / 95.96 / 95.45% | 0 | 0 |
| forceinline accessor `sample_at(bank, offset)` (by value, by reference, returning a reference) | 89–94% | +1 to +2 | — |
| `AttachmentSample *const &primary_bank` binding (Hill/Valley and HalfPipe style) | 75.09% | −1 | — |
| the same for `secondary_samples` only | 5 new swaps | 0 | +1 |
| indexed lead loop `primary_samples[i]`, or a per-iteration sample reference | 95.59% / 81.63% | +1 / −1 | — |

HalfPipe:

| Construct | Code | ΔC0 |
| --- | --- | --- |
| `(unsigned int)` byte casts | same | +7 (`id mod 1024` 476) |
| TurnoverDouble-style `compute_terminal_deltas` helper | 5 new swaps | +1 |
| `primary_samples` instead of `primary_bank` in the tail, or `primary_bank` in the lead | 93.06% / 95.83% | +2 / 0 (n 137 / 35) |

The costs do not simply add up, because C0 rounds to whole chunks. The largest code-identical combination
(Hill/Valley mesh + `segment_count_f` reload + per-segment helper + `(unsigned int)` casts) gives C0 0x580 and
n29, so the bank's `id mod 1024` is 413.

So the reachable range with identical code is:

| Function | Bank `id mod 1024`, reachable | Needed |
| --- | --- | --- |
| TurnoverDouble | 188 to about 413 | 0–9 |
| HalfPipe | 252 to about 477 | 0–11 |

What blocks each route:

- **Δn alone.** The TurnoverDouble function has 735 CSE slots in all, so +836 before slot 28 would be more than
  the rest of the function. Only code order decides n, and code order is fixed. Header forms give 0 or +1; a
  dead `this->f` store gives +2 each.
- **C0.** It needs −6/−8 blocks (192–256 fewer IL temporaries with the same instructions), or +24/+26. Every
  code-identical construct measured adds 0 to +7 blocks. Nothing measured lowers C0 without changing code.
  Inlined helpers are id-neutral: an expansion reuses freed temporaries (LIFO), so writing a loop as a
  forceinline helper, or a helper back into the body, leaves C0 unchanged.
- **The mod-4 side rules** (n50/n62, n6) are easy to keep, because a C0 change is ≡ 0 mod 4. But any Δn
  inserted before the secondary address must also be ≢ 2 (mod 4).

## 4. The siblings: a whole-function shift fixes them all (intervention)

Q13's per-slot pushes flipped a second site in Turnover, LoopBow and LoopTheLoop, because only the bank moved
past a temporary created before it. A `0:M` shift moves every temporary together, and each sibling then has a
byte-exact window:

| Function | Byte-exact `0:M` | In blocks |
| --- | --- | --- |
| Turnover | 724, 728 (M ≡ 0 mod 4 within 721–729) | +22 (≡ −10) with Δn 20 or 24 before the header |
| LoopBow | about 518–692 (tested every 8 from 520 to 688; 516 flips +0x311, 696 swaps) | pure C0 +17…+21 (≡ −15…−11) |
| LoopTheLoop | 652–753 at M ≡ 0 or 1 (mod 4); 760–872 give 5 other swaps | pure C0 +21…+23 (≡ −11…−9) |
| LoopOut | 581, 584, 585, 588, 589 | +18 (≡ −14) with Δn 5, 8, 9, 12 or 13 |

- Turnover's failures around its window: 720 flips +0x272; M ≡ 1 gives 10 swaps; M ≡ 2 gives 92.96%; M ≡ 3
  gives 99.70%.
- LoopOut is resolved in this sense: its endpoint temp 0x5bb has to reach 0x800–0x80a together with everything
  else (Q13's `804:924` and `1002:726` shifted the wrong slots).

The needed shifts differ by function, from −15 to −9 blocks or +17 to +27. No single house-style difference
covers them. Each one is larger than any code-identical construct measured.

## 5. Tool

`scripts/c2/cse_id_window.py` (new). It runs from snail-mail and reuses `cse_slot_trace.py`:

```sh
uv run python ../crimson/scripts/c2/cse_id_window.py <scratch> --out <dir> [--source f.cpp] [--chunks] \
    '28:830..850' '0:480..720/8' '0:832,28:3..14'
```

It traces once, then prints:

- C0 and the number of CSE slots;
- with `--chunks`, every chunk opened before C0 and its opener;
- for each phantom spec, the matcher result: exact, SIB swaps, or the normalized ratio.

The phantom recompiles run eight at a time in threads, about one second each.

## Open questions

- The other fix in address-order.md is to give the offset local a late pool-B id (≥ 0x179 in TurnoverDouble,
  ≥ 0x1f9 in HalfPipe). That needs pool B's first block to fill before the curve or middle loop is read. It was
  not explored here: locals appear to take ids at first reference, through `fe_symbol_get_storage` [inferred].
- Whether the originals put the bank in a different operand kind at these sites, as a load leaf through a
  CSE-available address (Hill/Valley's mechanism). That changes which rule applies, and it cannot be tested
  without code that differs somewhere.
- Why tree simplification (`simplify_conversion`, `emit_tree_as_tuples`) opens six chunks past the reader's
  peak in TurnoverDouble. It is the only part of C0 that is not a direct count of the IL.

## Corrections to other notes

- [cse-slot-count.md](cse-slot-count.md) §5:
  - LoopOut is resolvable by a whole-function shift (`0:581…589`, at M ≡ 0 or 1 mod 4).
  - The "flips" for Turnover, LoopBow and LoopTheLoop come from shifting only the bank. `0:M` windows exist for
    all three.
- snail address-order.md, residue table:
  - LoopTheLoop needs 9–11 fewer blocks, not 5–11. At −5 to −8 blocks (`0:768…872`) five delta-loop SIB bytes
    flip.
  - The TurnoverDouble and HalfPipe rows also need the secondary-address rule n(this+0x5c) ≢ 0 (mod 4) whenever
    the shift is not a multiple of 4.
