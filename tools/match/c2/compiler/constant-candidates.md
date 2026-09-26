# Constant candidates: which immediates count, and why a bool's stores do

C2.DLL 12.00.8966 (image base 0x10700000), `/O2` (so `/Ot`). This note decodes how the global allocator turns
immediates into class-13 constant candidates, which uses give a constant its benefit, and why the stores of a
`bool` local that is passed to a `bool` parameter always count. The allocator itself is in
[regalloc.md](regalloc.md).

Everything marked *verified* was observed with `scripts/c2/const_trace.py` on real compiles. The rest comes from
reading the disassembly.

## 1. Pipeline

`build_live_ranges` (0x10726d75) runs these steps in order:

1. `promote_immediates_to_candidates` (0x1072795a) walks every real tuple (flag bit 1) in IL order.
   - Before it looks at sources, it scans the tuple's destinations. A destination narrower than 4 bytes that is
     a part of a larger symbol marks the root symbol as partially written (`root+5 |= 0x80`, 0x10727985..0x107279b0).
     This applies to kind-1 operands that still have the placeholder home 0x107ae040, and to kind-2 operands.
     A part of class 3 (a temp) does not mark its root.
   - It then looks at the sources. Every kind-7 immediate goes through `tuple_allows_constant_candidate`
     (0x10727e73). Symbol and code addresses (kinds 3 and 4) are promoted as well, except in call and branch
     tuples. `lea` is skipped here and handled through its address mode.
   - An allowed operand is replaced by `make_constant_candidate_operand` (0x10727f41). This creates a kind-1
     operand (op 0x149) of the constant symbol for that value, with the placeholder home.
     **The new operand keeps the immediate's type.** A byte store's `1` becomes a byte-typed use of the
     shared constant `1`.
2. `assign_candidate_indices` (0x10727bd3) numbers the promotable symbols.
   - A part narrower than 4 bytes normally gets no index of its own. Its `+0x34` is pointed at the smallest
     containing part, usually the root, and every reference to it is tracked as that symbol (0x10727d11..0x10727d39).
   - If the root was marked partially written in step 1, each part gets its own index instead (the checks at
     0x10727d09 and 0x10727d0f).
3. Liveness, then the join loads (0x1072e5b9, not decoded here). Then
   `insert_upward_exposed_reloads` (0x1072e7cb). See §4.
4. Webs, then `score_live_ranges` (0x10724b25) in the global colourer. See §3.

## 2. Which tuples are eligible (0x10727e73)

The opcode is the x86 opcode (IL has already been lowered). Jump table at 0x10728190, indexed by the byte
table at 0x107281a0 for opcodes 1..0x2d.

| Opcode | Rule |
|---|---|
| `mov` (1) | Allowed, except `mov R, 0` where R is a kind-1 operand whose home is a physical register (home class ≠ 2). A register candidate's home is the placeholder 0x107ae040, which has class 2, so `mov candidate, 0` **is** promoted. |
| `cmp` (0x2f) | Allowed, except `cmp R, 0` under the same condition. |
| `add` (0x2d), `sub` (0x32) | Refused when the destination is esp or ebp (`g_reg_symbols[5]`/`[6]`). |
| refused outright | `enter`, `imul` (6, and `_imul3` 0xa3, `_imul2` 0xc1), `ret`, `in`, `out`, `rcl rcr rol ror sar shl shr` (0x25..0x2b), `shld`/`shrd` (0xca/0xcb), 0x11a (`LDZERO`), 0x166, 0x178 |
| everything else | Allowed. This includes `push`, `xchg`, `and`, `or`, `xor`, `test`, `adc`, `inc`/`dec` forms, and IL opcodes above 0xcb. |

*Verified* (on Snail Mail's set_snail_weapon): every `push imm`, `mov candidate, 0/1`, byte store of 0/1, a
switch's `sub eax, 0` and a `cmp mem, 0` were promoted, and no tuple was refused.

**One symbol per value.** Symbols are hashed by `value % 64` (0x1079d750). A symbol matches when the kind
matches and the low dword matches; the high dword is masked to 0. Type is ignored. A value first used once is
turned back into an immediate by `compute_block_local_sets`. A byte-typed use of 0 or 1 therefore makes the whole
function-wide 0 or 1 range byte-only, and so does any other byte-typed use of that value.

## 3. Benefit of a constant under /Ot

For a constant, `can_use_memory_operand` (0x107254f6) returns 1 immediately (it checks for class 13 at
0x10725501). So every promoted use is scored with `memory_operand_saving` (0x10725751, call site 0x107252d4):

- The "other operand" is the destination for opcodes whose `g_x86_op_flags` entry (0x107a0494) has bit 0x800.
  These are pure-destination opcodes: `mov`, `movzx`/`movsx`, `lea`, `pop`, `setcc`, `cmov` and the x87 stores.
  For every other opcode, the other operand is the first source. For `push` that is the constant itself.
- `cmp X, 0`: returns 0.
- The other operand is kind 2 (a memory symbol): returns **1**.
- The other operand is kind 6 with a direct symbol (+0x20) or a nonzero displacement (+0x24): returns **1**.
- Anything else: returns **0**. This covers a register or register candidate, a `push`, and a bare `[reg]`
  memory operand. A physical-register partner also gets operand flag `+0x11 |= 0x80`.

Each LOADCONST of the constant costs `load_saving` = 1 (0x10724f18 → 0x107254dc). Every value is scaled by the
block weight `1 << depth`.

So **`benefit(v) = Σ w·[store of v to memory, or read-modify-write/compare of memory with v] − Σ w·LOADCONST(v)`**.
Pushes, register moves and compares against registers add nothing.

*Verified* with `const_trace.py` on the first scoring pass (on Snail Mail's set_snail_weapon): a value used only
in pushes, register moves and compares against registers is queued at −1, its one load.

A byte-only constant range that is live across calls is allowed only ebx. The chooser (0x10732f7c) then charges
every range that interferes with it `100 × benefit` on ebx.

## 4. Why a bool passed to a bool parameter always stores to memory

The flag is a register candidate after `pass_mark_register_candidates` (its operands are kind 1 with the
placeholder home). Three steps then send its stores to memory before scoring. *Verified* with IL dumps
(`const_trace.py --il`) and hooks at 0x10731952 and 0x1072eb81.

1. **Argument widening creates a container.** `legalize_operand_forms` (0x10723155), case `IL_PUSHARG` with the
   esp destination, retypes the argument to a dword. For a kind-1 or kind-2 symbol source, it replaces the symbol
   with `symbol_get_part(sym, dword, 4)` (0x107232b2). For a 1-byte local this creates a 4-byte root that takes
   over the front-end name. The local becomes part `+0` of it.
   - The push then reads the dword root `#9`, while the stores stay byte stores to its part `#8`
     (`mov [#8^9+0 z1], imm`).
   - This happens in `lower_pending_arg_copies` (0x1072c275) during `pass_lower_function`.
2. **The byte stores mark the container partially written** (§1.1). As a result, the byte part `#8` gets its own
   candidate index (§1.2) and is never read: the pushes read `#9`.
3. **Block-end demotion.** `insert_upward_exposed_reloads` (0x1072e7cb) keeps a *pending* set per candidate.
   - A def or reload sets the bit. A use that finds the value available clears it.
   - At each block end the set is masked with `andnot live_out` (0x1072e82c). Every candidate still pending is
     passed to 0x107318e5 with `where = 0` (0x1072eb81).
   - That function (unnamed until now) undoes the pending tuple:
     - a pending reload (0x163) is freed, so its uses read memory;
     - a pending constant load is reverted to immediates;
     - a dead single-def temp is deleted;
     - a local's def gets `operand_make_sym` (0x10702edf), which makes it a **memory store**.
   - Every `#8` store and every `#9` reload in front of the pushes is demoted this way (the hook log lists each
     one).

At scoring, the flag's stores are therefore `mov [2:#8], [1:constant]`, and each saves 1 for its constant. The
final code is the familiar `mov byte [esp+x], imm` and `mov reg, dword [esp+x]; push reg`.

**Rule.** A 1- or 2-byte local that is passed directly as a 1- or 2-byte argument, and that is never read at its
own width, has all of its immediate stores counted as memory stores.
- Each store adds 1 to that value's constant benefit. Its byte type also makes the value byte-only.
- None of these change it: the flag's type (`bool`, `char`, `unsigned char`), its scope, where the reset sits,
  `true`/`false` literals, a reference or pointer alias, `register`, or `volatile`.
- It stops only when the local is read at its own width. For example, `char` or `int` passed to a `bool`
  parameter goes through `!= 0`, which reads the local. The local then stays a register candidate, and its stores
  become register moves that save 0. That changes the code: the flag gets a register plus `setne`.

Checked on Snail Mail's set_snail_weapon and SetJetPack (predicted and traced benefits agree), with a `char`
flag as the negative control.

## 5. Tool

```sh
uv run python scripts/c2/const_trace.py <scratch> --out <new dir> [--il]
```

The tool prints, per value:
- promotions and refusals;
- the uses that save 1 and the loads in the first scoring pass, and the benefit the range was queued with;
- a count of later rescoring events.

It also lists every block-end demotion. `--il` dumps the IL at the stock pass boundaries, entering
`build_live_ranges` and entering the global colourer. The run is fully preserving (whole-COFF, replay and
missing-stream checks).

## 6. Open questions

- 0x1072e5b9 (join loads) was not decoded. In every trace here each value got exactly one load.
