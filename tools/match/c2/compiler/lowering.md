# C2.DLL lowering and instruction selection (VC6 12.00.8966)

Covers the per-function passes between the global optimizer and register allocation, plus switch, x87,
__int64, intrinsic, call and address-mode lowering. The addresses are C2.DLL VAs. "/Ot" means the
favor-speed flag 0x107ac0b4 (/O2 turns it on, /O1 and /Os clear it). "/Og" is 0x107ac058, and "cpu" is
0x107ac0b0 (/G3../G6). Confidence is stated per item. "(inferred)" marks names inferred from code shape.

## 1. Pass map (driver 0x10757fc2, in order)

| pass | name | gate | what it does |
|---|---|---|---|
| 0x107281cd | pass_narrow_byte_lanes | always | byte-lane / AH-AL narrowing of `(x>>8)&0xff`, `x&0xff`, shift-by-8 chains |
| 0x107284d8 | pass_mark_register_candidates | acts only with /Og | non-volatile scalar symbols get placeholder home 0x107ae040 |
| 0x10728587 | pass_form_read_modify_write | always | `x = x op y` with memory x -> `op [x], y` |
| 0x107285f0 | pass_sizeopt | always | sizeopt.c: known-zero-high-bit tracking, drop redundant zero-extend/mask, narrow or widen op width |
| 0x10728ee5 | pass_remove_redundant_branches | always | fixpoint: jump-to-next, unreferenced labels |
| 0x1072906a | pass_if_convert | always | if/else diamonds assigning one var (or the return value) -> IL 0x18f select |
| 0x107290aa | pass_strength_reduce_mul_div | /Og | mul by constant -> lea/shl/add/sub chain; div by constant (/Ot) -> magic multiply |
| 0x1072930f | pass_select_address_modes | always | addr.c: fold defs into [base+index*s+disp]; address copies -> lea; add vs lea |
| 0x107294f3 | pass_merge_return_tails | /Og and **not** /Ot | cross-jump identical code before jumps to the exit label (dbcheck.c validates) |
| 0x10729511 | pass_lower_function | always | IL -> x86 opcodes (lower.c, lowerflt.c, cgintrin.c), legalization, two-address |
| 0x107296de | assign_parameter_homes | always | register params (fastcall/thiscall), stack offsets, homing of address-taken reg params |
| 0x1072c2e5 | pass_machine_peephole | /Og | load folding, inc/dec, cmp-with-0 elimination, and->test |
| 0x1070592f | cfg_rebuild | always | rebuild CFG (+ switch table edges) |
| 0x10706210 | cfg_reanalyze | always | markers, C4702, numbering, dominators, loops |

Switch lowering happens much earlier, in the IL reader (0x10714b7f -> 0x1074ec48). Tables are expanded
late (0x1073eb93); see section 11.

## 2. IL opcode map (derived from the lowering switch 0x10729c3c, tables 0x1072be0c/0x1072bf08/0x1072bd38)

- 0x145 nop/deleted; 0x146..0x14f are address-operand forms (see section 7); 0x148 is a float immediate (becomes `__real@`); 0x14a is &symbol+disp.
- Data movement:
  - 0x15a arg copy (push)
  - 0x15b copy; 0x15d/0x15e/0x1ad are other copy flavours (all lower to mov)
  - 0x15f convert (int widen/narrow and float)
  - 0x162 fst/round marker
  - 0x16a struct arg push; 0x16b struct assign
  - 0x16c return value (-> EAX plus marker 0x19e)
- Unary: 0x160 not; 0x161 neg.
- Arithmetic:
  - 0x16d add; 0x16e sub
  - 0x16f mul (imul 0xc1 two-operand; one-operand imul 6 for bytes)
  - 0x170 multiply-high (imul/mul one-operand, EDX:EAX)
  - 0x175 div; 0x176 mod (result in EDX)
- Shifts: 0x171 shl; 0x177 shr/sar (unsigned uses shr).
- Logic: 0x172 and; 0x173 or; 0x174 xor.
- Compare and control flow:
  - 0x17d cmp
  - 0x184 call; 0x185 jcc (condition remapped signed->unsigned via 0x107a02e8 for unsigned operands); 0x186 jmp
  - 0x18b exception edge ([branch-variants.md](branch-variants.md)); 0x18d switch; 0x18f select
- Other:
  - 0x178 copy that also produces flags / fixed register (low confidence)
  - 0x190 intrinsic (id at +0x20); 0x192..0x19a and 0x1a5 are EH; 0x1a7 lowered to x86 `ret` (opcode 8) with a 0 operand (medium); 0x1a8 bitfield/union merge; 0x1ab/0x1ac unreachable/assume
- Type word +0xa: class nibble (0x1000 signed int, 0x2000 unsigned int, 0x4000 float, 0x5000 aggregate) with byte size in the low 12 bits.
- Machine pseudo 0x166 is a late multi-instruction op whose first constant operand selects the expansion in finlower 0x1075a6ff (0x183 is signed modulo by a power of two).

## 3. Byte-lane narrowing — 0x107281cd / 0x10728217 (medium)

Walks tuples backwards. For int ops of 4 bytes or less whose temp sources are defined by
- add/or (0x16d/0x173),
- shl/shr by 8 (0x171/0x177),
- and with 0xff/0xff00 (0x172), or
- cmp (0x17d),

`classify_byte_lane_source` 0x1071ef4b decides which byte lane is live. `make_byte_lane_operand`
0x10768fb8 then rewrites the use as a byte sub-register copy (type 0x1001, plus a 0x149 sub-register
view). This is where `(x >> 8) & 0xff` becomes an AH-style byte access and `(hi << 8) | lo` becomes byte
stores. The helper 0x1071f115 looks through widening converts (0x15f).

## 4. Read-modify-write formation — 0x10728587 / 0x1072c730 (medium)

`x = x op y` where x is not a single-def temp (a memory or global variable) is rewritten into one
operation writing x. That later becomes `add [mem], y`, `or [mem], imm`, `shl [mem], cl` and so on.
- Handles add, sub (as add with negation), and, or, xor and shifts.
- For shifts and non-commutative ops, only x on the left qualifies.
- 8-byte operands are allowed only for xor.
- 0x1072dc51 searches add/sub chains, so `x = x + a + b` qualifies.

**Matching:** `g = g + k` and `g += k` produce the same code. `g = k + g` also works for commutative
ops. `g = g - k` works; `g = k - g` does not.

## 5. sizeopt.c — 0x107285f0 (medium)

`sizeopt_block` 0x1072865c alternates a forward scan 0x10728696 and a backward scan 0x10728a34 to a
fixpoint (ICE at sizeopt.c:69 after 50 rounds).

The pass tracks per-symbol known-zero high bits in symbol +0x31: 0x18 means the value fits in a byte,
0x10 means it fits in a word. With that it:
- deletes zero-extensions from unsigned char/short (0x15f from 0x2001/0x2002) and `and x,0xff/0xffff`
  when the source is already known narrow (0x1074bc80);
- narrows ops to byte width when all operands allow it (0x1072aa3c + 0x1072db07 -> 0x1071f38c);
- widens byte/word ops to dword when legal. Memory operands are widened only if the access stays inside
  the symbol, alignment allows it, and they are not volatile (0x1072ab99).

Without /Ot there is an extra pass, 0x10791f04, that narrows ops wider than 2 bytes to 16-bit (shorter
immediates). Narrowing an `and` to 16-bit is disabled under /Ot (0x1072db07).

**Matching:** when an unsigned char/short local is used as an int, /O1 and /O2 can differ in
movzx-versus-direct-use and in 16-bit operand prefixes.

## 6. Mul and div by constant — 0x107290aa (/Og) (high)

### Multiply (IL 0x16f)
Applies to int constants, not 64-bit. The search is `find_mul_decomposition` 0x10751662. It is memoised
in hash 0x1079e894, which 0x107291bd seeds with 1, -1, 2, 3, 4, 5, 8 and 9.

Operations and costs (table 0x107ae0b8):

| op | form | cost |
|---|---|---|
| 1 | neg | 1 |
| 2 | x*m<<k + x | 2 |
| 3 | x*m<<k - x | 2 |
| 4 | x - x*m<<k (with neg) | 3 |
| 8, 0xa, 0xc | lea scale x2, x4, x8 | 1 |
| 9, 0xb, 0xd | lea [x+x*2/4/8] (x3, x5, x9) | 1 |

Budget (`expand_mul_by_constant` 0x107514c0; the chain must cost strictly less than the budget):
- /Os (no /Ot): 2, so only one-op forms: x3, x5, x9, x2/x4/x8 and neg.
- /Ot with /G3 or /G4: max(log2 n, 3) + 6.
- /Ot with /G5 or /G6: 10.

Even n: the odd part is solved with budget-1, then shifted. Shifts by 1..3 become lea scales (k ≤ 3),
larger shifts become shl (0x10751a54).

Factors are tried in the order 9, 5, 3, then n-1, n+1, then 1-n. A cheaper result replaces a previous
one only if it is strictly cheaper, so on ties the first-found (factor) form wins.

When no chain is found, lowering emits `imul r, r/m` (0xc1). Constants of r/m, imm form go through the
legalizer as `_imul3`. A power of two is always `shl` (0x10729c3c case 9), even without /Og.

### Divide (IL 0x175)
Requires /Og and /Ot. The divisor must be a constant that is not a power of two, the dividend must not be
a constant, and the size must not be 8 bytes.
- **Signed** (0x1075a1b0):
  - `mov eax,M; imul x` (mul-high 0x170);
  - `add edx,x` if d>0 and M<0, or `sub edx,x` if d<0 and M>0;
  - `sar edx,s`, then `mov eax,edx; shr eax,31; add edx,eax`.
  - Magic numbers for d=3..12 come from the table at 0x107ae0d8+8d (3:0x55555556/0, 5:0x66666667/1,
    6:0x2AAAAAAB/0, 7:0x92492493/2, 9:0x38E38E39/1, 10:0x66666667/2, 11:0x2E8BA2E9/1,
    12:0x2AAAAAAB/1). Other divisors use the Hacker's-Delight algorithm (0x1075aa37).
- **Unsigned** (0x1076943d): table 0x107ae140, entries {M, add, s} (7 is the add variant
  `((x-hi)>>1)+hi` with s-1), otherwise computed.
- **Modulo (0x176) is never strength-reduced by magic numbers.**

### Power-of-two divide and modulo (in lowering, 0x10729c3c)
- Unsigned: `shr`.
- Signed `/2^k`:
  - under /Ot, any power of two: `cdq; and edx,2^k-1; add eax,edx; sar eax,k`. For /2 this is
    `cdq; sub eax,edx; sar eax,1`.
  - without /Ot, only /2 gets the sequence; other powers of two use idiv.
- Signed `%2^k` under /Ot: pseudo 0x166/0x183, expanded in finlower (0x1075a6ff) to
  `and eax,0x80000000|(2^k-1); jns L; dec eax; or eax,-2^k; inc eax; L:`. A negative constant divisor
  uses a cdq/xor/sub/and/xor/sub sequence. Without /Ot: idiv.
- Constant 0 divisor: warnings C4723/C4724 (0x2d3/0x2d4).

**Matching:**
- `x/10` is magic-multiplied at /O2 and idiv at /O1; `x%10` is always idiv.
- `x*k`: at /O1 only k in {2,3,4,5,8,9} (times a power of two with the shift) is decomposed; at /O2
  longer lea/sub/add chains appear.
- The decomposition runs on IL. Register allocation later decides lea vs add.

## 7. Address-mode selection — addr.c, 0x1072930f / 0x1072ac94 (high)

Backward walk over the tuples. For each memory operand (kind 6, size ≤ 4, not 3) and each 4-byte int op
with a temp destination, `fold_address_expression` absorbs single-def temp defs into one addressing tuple:
- copy 0x15b;
- add 0x16d (constant -> disp, symbol -> symbol, temp -> base or index);
- sub 0x16e (constant);
- mul 0x16f by 1/2/4/8 and shl 0x171 by 1..3 -> scale.

Only one scaled index is allowed. When the base temp is redefined in between, folding is blocked
(0x1075235f). The result is encoded as an address-operand form. The kind-5/6 layout is: +0x20 symbol,
+0x24 disp, +0x28 base, +0x2c index, +0x10 low nibble = scale code (1→0, 2→1, 4→2, 8→3).

| form | shape | non-memory result |
|---|---|---|
| 0x146 | disp only | `mov r, imm` |
| 0x14a | &sym+disp | lea, or `add r,&sym` if out of the symbol's extent |
| 0x14b | [sym] | mov |
| 0x14c | base+disp | **dest == base temp -> `add r,disp` (`sub r,-disp` if disp ≤ 0); otherwise `lea r,[base+disp]`** |
| 0x14d | base+index*s+disp | scale 1, no disp and dest == base -> `add base,index`; otherwise lea |
| 0x14e | sym+index*s+disp | lea |
| 0x14f | index*s+disp | no disp and dest == index -> `shl index,log2 s`; otherwise `lea r,[index*s+disp]` |

`mov r, <kind-5 address>` is turned into `lea` (0x10710648 / 0x1075e7b0). The ADD-vs-LEA decision
is made on whether the destination temp is the base temp at this point, which is the def-link rule from
the crimson notes.

After register allocation, finlower (0x1073536c) turns `lea r,[r+1]` into `inc r`, `lea r,[r-1]` into
`dec r`, and other `lea r,[r+k]` into `add r,k`.

**Matching:**
- `p = q + 4` (a new temp) gives lea; `p += 4` gives add.
- `i*8 + base` folds into `[base+i*8]` only if the multiply feeds the address directly, not through a
  shared temp that has other uses.

## 8. If-conversion — 0x1072906a (medium)

Pattern: `if (c) x = a; else x = b;` or `return c ? a : b;` in a diamond (0x1072d139), integers of 4
bytes or less. Both strategies are dry-run for cost:
- 0x107495af: carry mask, `cmp; sbb r,r; and r,(a-b); add r,b`, with neg/not variants;
- 0x10749d61: `xor r,r; cmp; setcc r8; dec r; and r,(a-b); add r,b`.

The select is accepted if min(cost) ≤ threshold, from byte table 0x107ac1e4 indexed by
(/Ot ? cpu-4 : 2): /Ot G4 9, G5 10, G6 12; /Os 12. Lowering (0x107506a7) emits the cheaper form; on a
tie, the sbb form. No cmov is ever emitted (not referenced).

**Matching:** the same logic written as `x = c ? a : b` or as if/else gives the same result; a diamond
with side effects stays branchy.

## 9. Lowering core — 0x10729511 / 0x10729b6e / 0x10729c3c (high)

`pass_lower_function` lowers each tuple except IL 0x15a/0x16a (lowered together with their call). Floats
go to lowerflt (0x10762fc3), and >4-byte ints first go to __int64 lowering (0x1075ac4f). After the
opcode switch, `legalize_machine_tuple` 0x1072289e does the following:
- enforces fixed registers (EAX/EDX for mul/div, CL for shift counts via 0x1071eb37);
- enforces two-address form (0x1072ccac: the destination is tied to src0 if single-def, else a copy is
  inserted);
- swaps operands to satisfy encodings; for cmp it inverts the jcc through 0x107a09a8.

A second loop then runs `propagate_lowered_copy` 0x1072a632 (forward-substitutes copies and deletes them)
and `set_flags_effects` 0x10724028 (EFLAGS def/use on each machine op, register 0x107adcd8).

Integer extension (IL 0x15f, case 2):
- **signed:** `movsx` always.
- **unsigned:**
  - `movzx` if the destination is 16-bit or /Ot is off;
  - under /Ot, if the source can be read as a dword (register temp): `mov r,src; and r,0xff/0xffff`;
  - under /Ot otherwise (byte/word memory): `xor r,r; mov r8/r16,src`.

  This is why VC6 /O2 shows `xor eax,eax; mov al,[x]` and /O1 shows `movzx`.
- Constant sources fold to mov.

Other rules:
- mul: `imul r,r/m` (0xc1) for sizes above 1, one-operand `imul` for bytes.
- Multiply-high: one-operand imul (signed) or mul (unsigned).
- shr vs sar comes from signedness.

## 10. Parameters and machine peepholes

- 0x107296de binds parameters.
  - Calling convention = function +0x14 & 0x1c: 4 __fastcall and 0x18 use {ECX,EDX}; 0x14 __thiscall
    uses {ECX}.
  - Only int params of 1, 2 or 4 bytes go in registers, in order (0x1072c01b).
  - Stack params start at [ebp+8] (0xc for flagged functions, 0x10729904) with 4-byte slots.
  - Register params whose address is taken (symbol +0x14 & 0x100) are stored to their home at entry.
- 0x1072c2e5 (/Og):
  - folds single-use loads into the instruction as memory operands;
  - `add r,1` becomes `inc`, `sub r,1` becomes `dec` (and ±1 with the opposite sign), unless the flags
    are consumed;
  - deletes an `and x,m` before `shr x,n` when the and only clears shifted-out bits;
  - 0x1072d549 deletes `cmp t,0` when t's defining arithmetic already set usable flags (per-op tables
    0x1072d8f0/0x1072d900; shifts must have a count of 1..31);
  - `and` whose result is otherwise dead becomes `test` (0x1072d776).
- Without /Og these peepholes do not run. finlower still turns `cmp reg,0` into `test reg,reg` (0x107359d9).

## 11. /O1 return-tail merging — 0x107294f3 (medium)

With /Og and without /Ot, for each jmp to the function's exit label, identical instruction runs (tuple
equality 0x1070e8ba) before two such jumps are merged. A differing return value is routed through one
new temp. dbcheck.c (0x1078e199) verifies that temps defined in the run are local to it.

**Matching:** at /O1, several `return f(x)+1;` sites can collapse into one shared tail. At /O2 they stay
duplicated.

## 12. Open questions / uncertainty
- The exact per-opcode flag-validity tables used by cmp elimination (0x1072d8f0/0x1072d900) were not
  decoded row by row.
- sizeopt helpers 0x1072a86d/0x1072a97d/0x1072a9c6/0x1072aa01/0x1072cdec were not read in depth.
- 0x107294f3 is read as return-tail merging from its structure (exit label, jmp 0x186, new temp). The
  exact equality criteria are in 0x1070e8ba/0x1077f13c, which were not read.
- IL 0x178 and 0x1a8 semantics are low confidence.
- Two calling-convention codes (0x18, 0x40) are unresolved.


# Appendix A: switch lowering (switch.c)
## Switch lowering (switch.c)

**Where.** Switches are lowered while the IL is read, before any optimization. The IL reader 0x10714b7f handles record 0x2b: it copies the selector into a fresh temp (0x15b), reads the body, then calls `lower_switch_statement` 0x1074ec48 (at 0x107153ce). The case list comes from IL records 0x2c (list head, which holds the default label) and 0x2d (one case each, appended in C1's order). C2 treats the list as sorted ascending: the span is computed as last.hi - first.lo and runs are merged by adjacency. C1 presumably emits the cases sorted; this was not checked inside C2. The switch-jump tuple 0x18d survives until one of two places: the main lowering (0x10729c3c case 0x18d, dec chain only) or the late pass `lower_switch_pseudo_ops` 0x1073eb93, which runs after the scheduler.

**Case pruning (0x1074ecd9).** Cases whose target is the default label are dropped. So are cases whose target block's first real tuple is an unconditional jmp to the default, or to where the default block jumps. Consecutive values with the same target are merged into [lo,hi] ranges. Stats (0x1074f2f0): n = number of nodes, ncmp = singles + 2*ranges, span = max - min (int64).

**Strategy (0x1074eea0, recursive).** T = g_switch_thresholds[0] (0x107a3280): 4 under /Ot, 8 otherwise.
1. n == 0: `jmp default`.
2. ncmp < T: compare chain (0x1074f642).
3. Selector wider than 4 bytes: jump table if span <= 4*ncmp, else split.
4. /Ot: jump table if span < 255, however sparse (0x1074ef45). Otherwise jump table if span <= 4*ncmp.
5. Not /Ot: jump table if span fits in 32 bits and chain bytes > table bytes. Chain bytes (0x10776430) = sum over bounds of ((imm8 ? 3 : 6) + 3). Table bytes (0x107764a8) = min(4*span, span + 7 + 4n) + 11. Otherwise the density test from step 4 (span <= 4*ncmp).
6. Otherwise, binary split (0x10759f8c). 0x10759fd0 scans for a dense leading run: gaps <= 3 and count*3 >= range+1. If that run has more than T nodes, the split is at its end; otherwise at n/2. The split node emits `cmp x,hi; jg Lright; cmp x,lo; je/jge target` (0x1075a0e6), followed by the left part (smaller values), then `Lright:` and the right part. Each part is decided again from step 1.

**Jump table (0x1074f4e0 + 0x1074fbee).** If min != 0, `sub x,min` is applied to the selector temp in place. Then `cmp x,span; ja default` (unsigned) is emitted. g_switch_range_check 0x107ac3e8 is always 1, so the check is skipped only when the default is unreachable or when the int64 guards already bound the selector. The late expansion then picks one of two layouts:
- Plain: `jmp [tbl + x*4]`. The dword table has one entry per value, and gaps point to the default (0 if the default is unreachable).
- Two-level: used when k < 256 and 11 + 4k + (/Ot) < 3*(span+1), where k is the number of case nodes (0x107439a3). The index load is `movzx r32, byte [btbl+x]` without /Ot, and `xor r,r; mov r8, byte [btbl+x]` under /Ot. Then `jmp [dtbl + r*4]`. dtbl lists the distinct targets in the order they first appear in the case list, with the default appended last only if there are holes. btbl holds per-value indices, and holes use the default's index.
- Tables are 4-aligned data (0xbb `_data`), placed after the function's last kind-0x18 tuple, i.e. at the function end.

**Compare chain (0x1074f642).** Cases are tested in list (ascending) order.
- Single value: `cmp x,v; je L`.
- Range: a lower-bound test to the default first. This is `jl lo` when lo == 0, or on the first node when lo != 1; otherwise `jle lo-1`. Then `cmp x,hi; jle L`.
- The chain ends with `jmp default`. When the default is unreachable, the last case is not tested and becomes a `jmp` to its target.
- Jcc codes: 1 eq, 3 lt, 4 gt, 5 le, 6 ge. They become unsigned forms at lowering for unsigned selectors (table 0x107a02e8).
- Byte narrowing (0x1074fa7e): when the selector is a widened char (0x15f from size 1) and every case value fits in that char type, the compares become byte compares (`cmp al,imm8`). This applies to the chain path only.

**Dec chain (0x1074f888 -> 0x1074f970).** Conditions: /Og, selector size <= 4, only single values, all values >= 0, and at least one delta is 1 or 2 or fits in imm8 while the value itself does not. Emitted as `mov t,x; sub t,v1; je L1; sub t,v2-v1; je L2; ...; jmp default`. The 0x18d tuple carries flag bit0 and is expanded in main lowering (0x10729c3c case 0x18d).

**__int64 selectors (0x1074f382).** With >= 4 compares and all values fitting in 32 bits, 64-bit guard compares to the default are emitted (signed: both bounds, unsigned: the upper bound only), and the switch continues on the truncated 32-bit value.

**Unreachable default (0x1074ec80, /Og only).** Detected when the default block starts with IL 0x1ab carrying a 0x1ac constant 0, most likely `default: __assume(0)` (medium confidence). Effects: no range check, no default slots, and the chain's last case is not tested. When some case block jumps to the same place as the default block (0x1074d9d0), 0x1074eea0 also tries folding the default into the case list and keeps that version if its stats still qualify (low confidence on the details).

**Matching implications**
- Only T separates a compare chain from a table/tree: `ncmp < 4` under /O2, `< 8` under /O1 (ncmp counts a range as 2). Cases that go to the same label as `default:` are removed before counting.
- /O2 builds a jump table for any switch with >= 4 compares and span < 255, even a very sparse one. It then becomes a byte-indexed two-level table if 3*(span+1) > 4k+11.
- Adding or removing a case that lands on the same target as its neighbour changes n and ncmp (run merging), and can flip the strategy.
- A byte-table index load is `movzx` under /O1 and `xor reg,reg` + `mov reg8` under /O2.
- The first case value is always subtracted (`sub eax,min`) unless it is 0. The range check is always unsigned `ja`.
- Dec chains (`sub/je` sequences) appear only under /Og, and only with small non-negative single values.
- `switch` on a char produces byte compares only in the compare-chain form.
- Binary trees split at n/2 unless a dense leading run of more than T cases exists. Left (lower) subtrees are laid out first.

**Uncertainty.** Row entries [1] and [3] of 0x107a3280 are not referenced by code (the 255 limit is a literal). The /Os-vs-/Ot switch keys only off 0x107ac0b4; how /Od sets it was not checked. The exact scan rule in 0x10759fd0, which also compares 2*lo_j - lo_prev against the next lo, is paraphrased.


# Appendix B: intrinsics, block copies, calls and returns

## Intrinsics, block copies, calls

### Block / struct copies
- IL 0x16b = struct assignment, 0x16a = struct argument push. In `lower_by_opcode` (0x10729c3c case 5): size in {1,2,4,8} and no count operand -> `lower_small_block_copy_as_scalar` 0x10751e0d rewrites to scalar 0x15b/0x15a (8 bytes go through the __int64 path -> two dword movs/pushes). Otherwise `lower_block_copy` 0x10756732 -> memcpy intrinsic (id 0xac) via 0x10756886 -> `lower_intrinsic` 0x10754cc8.
- 0x16a struct args: size rounded up to 4 (0x10751e6f), `sub esp,N` (or `mov eax,N; call __chkstk` when N >= /Gs threshold, 0x10761f67), then memcpy to [esp].
- Core generator `emit_string_block_op` 0x107557e1 (shared by memcpy/memset/strcpy/strcat/strset):
  - small = constant count && (count>>2) <= 4 for copies (so up to 19 bytes), <= 5 for fills (up to 23 bytes) (0x10755ad7).
  - small && /Ot && /G4+ (0x107ac0b0 > 3): unrolled `mov r,[src+k]; mov [dst+k],r` per dword (0x1075a554), then word/byte tails.
  - small but /Os or /G3: a chain of single `movsd` / `stosd` (no rep), plus `movsw`/`movsb` tails.
  - otherwise: `mov ecx,n>>2; rep movsd` (or `rep stosd`), tail constant: `movsw` if n&2, `movsb` if n&1; variable n: `shr ecx,2; rep movsd; mov ecx,n; and ecx,3; rep movsb`.
  - pinned regs: EDI dst, ESI src, ECX count, EAX fill value.
- memset: constant fill byte replicated to a dword; count constant 0 -> call removed; a count known to be a multiple of 4 (e.g. `n & ~3`, or 4-aligned local array) switches to dword elements with no tail (0x10755ea6).

### Intrinsic ids (0x190 +0x20) handled by 0x10754cc8
Identified by behavior (the name table 0x107a3ac0 seems off by one, so treat names as inferred):
- 0xd/0xe/0xf abs (char/short/int): `cdq; xor eax,edx; sub eax,edx` (cbw/cwd for smaller) in EAX/EDX.
- 0x10/0x11 fabs, 0x5c/0x5d sqrt, 0x6a/0x6b sin, 0x6e/0x6f cos, 0x47 dprod: opcode map 0x107a69c8 (x87, lowered in lowerflt).
- 0x9f/0xa1 rol, 0xa0/0xa2 ror (_rotl/_lrotl, _rotr/_lrotr); 0xa8/0xaf/0xe0 `in`, 0xa9/0xb0/0xe1 `out` (port operand converted to 16-bit, DX).
- 0xa3 _strset, 0xa4 strcpy, 0xa5 strcmp, 0xa6 strcat, 0xa7 strlen, 0xaa memcmp, 0xac memcpy, 0xad memset, 0x96/0x97 sized block copy/fill (unknown source construct).
- 0xb1 _enable (sti), 0xb2 _disable (cli); 0xdb setjmp -> `__setjmp3` (+2/3 extra args for SEH/C++ EH); 0xde _alloca (sub esp / __chkstk, result = esp); 0xdf va_start-like (address of last param + rounded size); 0xe5/0x153 _ReturnAddress/_AddressOfReturnAddress (`__$ReturnAddr`); 0x184/0x186..0x189 profiling hooks (__DLP_Profiling@8, __CAP_*); 0xd7/0xd9/0xda/0x17a/0x17b/0x17d EH (0x10767609); 0xd8 -> 0x10766828.
- Code shapes: strlen = `or ecx,-1; xor eax,eax; repne scasb; not ecx; dec ecx` (0x107564b6); strcpy = scasb length+1 then movsd/movsb copy; strcat = scasb on src, scasb on dst, `dec edi`, copy; strcmp = two-bytes-per-iteration compare loop with sbb result (0x107627dd); memcmp = `repe cmpsb` (0x1077159e).
- strcmp(x, "literal") becomes the memcmp form 0xaa with a compile-time length (strlen+1) (0x10754cdf); strcat with a literal source uses the compile-time length too.

### Calls, arguments, returns
- Args are 0x15a tuples placed before the call in IL order; `convert_arg_copies_to_push` 0x1072e095 turns each into `push` (0xd). The push order is the front end's IL order (right-to-left). Float args are not pushed: `sub esp,N` + `fstp [esp]` (see 0x1076cb52 assertion). 16-bit args are widened to a dword push; 8-byte args become two pushes (0x1072e210).
- Register args (0x1072c01b): conv 4 (__fastcall) and 0x18 use ECX, then EDX, for the first int args of size 1, 2 or 4. Conv 0x14 (__thiscall) uses ECX only. The same routine homes incoming register params in 0x107296de.
- Stack cleanup (0x1072df42): conv 0 (cdecl) or 0x40, when the callee lacks flag 0x80, gets `add esp,N` right after the call (N = sum of args rounded to 4). All other conventions record N at call+0x20 (callee pops). This pass does not merge `add esp` across calls.
- /GZ: `mov tmp,esp` before the args; after the call `cmp tmp,esp; call __chkesp` (0x1076cb52).
- Return value (IL 0x16c, case 6 of 0x10729c3c): `mov eax/ax/al, value` plus marker 0x19e (EAX live to ret). When the value is a single-def temp, its defining insn is retargeted to EAX, so no copy is left. Floats return in ST0 (lowerflt), 8-byte values in EDX:EAX (0x1075ac4f), structs through the hidden `___$ReturnUdt` pointer (set up at IL read, 0x107181a8).
- IL 0x148 float immediates become `__real@<sz>@<hex>` constant-pool symbols (0x10763ea3). So float constants are always memory operands, except fldz/fld1 (not checked here).
- 0x1072c993: indirections (0x14c) whose pointer is `add p,const` or `lea` get folded into [base+index*scale+disp] memory operands (post-lowering address folding).

### Matching implications
- Struct copies of exactly 1/2/4/8 bytes are scalar moves. 3/5/6/7 and 9+ bytes go through movs.
- Under /O2 on G5/G6, constant memcpy/memset up to 19/23 bytes becomes register mov/store sequences. /O1 or /G3 gives `movsd` chains instead. Anything larger gives `rep movsd` plus movsw/movsb tails.
- For inlined byte memcpy with variable n, the `shr ecx,2 / and ecx,3` pair gives it away.
- strcmp against a literal gives `repe cmpsb` with an immediate count, not a byte loop.
- __fastcall uses ECX/EDX only for integer args of 4 bytes or less. __int64, float and struct args always go on the stack.

### Uncertainty
- The mapping from intrinsic id to C function name is inferred from code shape. The ids of 0x96/0x97, 0xdf, 0x177, 0x17e and case 7 (0x11b..0x14b) are unresolved.
- The meaning of conv 0x18 and 0x40 is unknown.
- The exact semantics of IL 0x178 are low confidence.


# Appendix C: x87 and __int64 lowering

## x87 float lowering (lowerflt.c) - 0x10762fc3
Entry from lower_dispatch 0x10729b6e for any tuple with float type or an x87 opcode (bit0 of 0x107a0494[op]). Keeps a model of the FP stack (g_fp_lower_depth 0x1079903c, g_fp_lower_stack_syms 0x10799040); when 8 values are live (depth==7) it spills the deepest via fstp to a compiler temp (0x1076ea17/0x1076ea81).
Dispatch (table 0x10763ae4): 0x15a arg push, 0x15b copy, 0x15f convert, 0x161/0x162 fchs/fst, 0x16c return, 0x16d-0x16f add/sub/mul, 0x175 div (C4723 on /0.0), 0x178 fixed-reg copy, 0x17d compare, 0x184 call, 0x190 intrinsic, 0x19e result.
- Pre-pass under /Ot only (0x10763761 -> 0x10763b3c): float copy memory->memory, float argument pushes from memory, and ==/!= compares against a non-zero float constant are re-typed to integer (mov/push dword(s), cmp dword,imm). Exception: with /Og && !/Op, if either side is a kind-2 symbol (register candidate) it stays x87. So /O2 code copies float struct members with mov eax,[..]/mov [..],eax while /O1 (no /Ot) uses fld/fstp.
- Constants (0x10764555): without /Ot, 0.0 -> fldz, 1.0 -> fld1; with /Ot constants are always fld [__real@...] from memory.
- Arithmetic (0x10763d93 + 0x1076450b): left operand loaded, right operand used as memory operand if not a stack temp; if both on the stack the p / r forms (faddp, fsubrp, fdivrp...) are chosen by which is on top. IL->x87 map 0x107a58f8.
- Compare (case 0x17d, 0x107631e3): fcomp mem or fcompp (both on stack), then fnstsw ax + sahf-pseudo (0xae) with conditions remapped to unsigned (0x107a02e8). No fcomi/fucom/fucomi opcodes are referenced anywhere (never emitted, even /G6). The sahf pseudo is probably rewritten to test ah,mask later (finlower 0x1073536c touches 0x6e/0xae at 0x1077ccb6) - NOT verified.
- float->int (0x15f): __ftol call (result EAX) by default; with -QIfist (0x107ac088) and dest not unsigned __int64: fistp qword [temp] then mov low dword (always a 64-bit fistp temp).
- int->float: signed (or >4-byte) source in memory -> fild directly; register source stored to a temp first (mov [tmp],r; fild [tmp]). unsigned 32-bit -> 64-bit temp {x,0} + fild qword. /Op (0x107ac0a4) forces a store/reload after fild unless the result is copied straight into a variable.
- float->float: widening free; narrowing (double->float) folds into fstp when the only use is an assignment of the same width, otherwise store+reload.
- Arguments: float arg = [fld if in memory] + sub esp,N + fstp [esp]; when the consumer is an intrinsic the value stays on the x87 stack.
- Returns: value left in ST0 (fld if not already a stack temp). Float call result unused -> fstp st(0) (0x107702ca).
- Intrinsics (0x1076f751): fabs always inline; sqrt, sin, cos, tan(fptan+pop), atan(fld1;fpatan), atan2(fpatan), log/log10(fldln2/fldlg2+fyl2x) inline only when /Og && !/Op; fmod inline (fprem) needs /Ot too. Otherwise a __CI<name> helper call (0x10771a04) with args on the x87 stack.
- -QIfdiv (0x107ac080) and -QI0f (0x107ac084) are only read by the emitter 0x1073ebea, not by lowering.

## __int64 lowering (lower.c) - 0x1075ac4f
Called for any tuple whose size (or first source size) is >4 bytes (0x10729c3c) and from float lowering/others. Operands are split into 32-bit halves by 0x1075b521 (memory +0/+4, temp pairs EAX:EDX).
- add/sub/and/or/xor/not/neg: low half normal op, high half op from table 0x107a0ba8 (adc, sbb, and, or, xor, not; neg = neg lo; adc hi,0; neg hi). /Og: and/or with a constant half of 0/-1 collapse to mov (0x10769e93).
- mul: if both inputs are 32-bit-sized values -> one imul (signed) or mul (unsigned) producing EDX:EAX; otherwise __allmul.
- div/rem: always __alldiv/__allrem/__aulldiv/__aullrem (C4723/C4724 warning on constant 0).
- shifts: /Og and constant >=32 -> inline (shl: hi=lo, lo=0, shl hi,n-32; shr: lo=hi, hi=0, shr lo,n-32; sar: lo=hi, sar hi,31, sar lo,n-32; nothing extra when n==32). Everything else calls __allshl/__allshr/__aullshr (count in CL, value EDX:EAX). Intrinsics 0xe9/0xea/0xeb produce shld/shrd + shl/shr/sar inline (0x1076de65) - where the front end emits those intrinsics is unknown.
- compares (0x17d feeding a branch): ==/!= against 0 or -1 -> or/and halves + one cmp; otherwise cmp high + jcc(s) (signed conds for signed types), then cmp low + unsigned jcc.
- conversions: 64->32 take low half; signed 32->64 = cdq (forces EAX/EDX); unsigned 32->64 = hi 0; narrower sources are first widened to 32 bits.

## Matching implications
- Choice of /O1 vs /O2 (/Ot) changes float code shape: fldz/fld1 vs memory constants; fld/fstp vs integer mov for float copies; x87 vs integer compare for f==const.
- /Op adds store/reload after int->float conversions and disables inline transcendental intrinsics and the /Ot float->int-mov trick for register-candidate symbols.
- Casting float to int always calls __ftol unless -QIfist.
- unsigned->float is more expensive (64-bit fild through a temp) - (float)(int)u gives a different shape than (float)u.
- __int64 shifts by constants <32 become __allshl calls (unless compiled as the 0xe9.. intrinsics); shifts >=32 inline only with /Og.
- (__int64)a * (__int64)b with 32-bit a,b gives a single imul/mul instead of __allmul.

## Uncertainty
- sahf -> test ah,mask rewrite location not confirmed.
- Exact semantics of 0x10763d24 mask bits (1 = equal is certain from usage with 0.0/1.0).
- IL 0x178 and 0x19e roles (fixed-register copy / result pseudo) are inferred.
- Constant tables 0x10799440/0x10799450 and intrinsic table 0x1079bdc0 are zero in the file (runtime-initialised); 0.0/1.0 inferred from fldz/fld1 selection.
- 64-bit return of struct via 0x19e case with rep+0x37 (opname table says lods, likely movs) is unclear.

