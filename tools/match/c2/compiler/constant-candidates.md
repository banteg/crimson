# Constant candidates: which immediates count, and why a bool's stores do

C2.DLL 12.00.8966 (image base 0x10700000), `/O2` (so `/Ot`). This note decodes how the global allocator turns
immediates into class-13 constant candidates, which uses give a constant its benefit, and why the stores of a
`bool` local that is passed to a `bool` parameter always count. It ends with the set_snail_weapon case from
snail-mail. The allocator itself is in [regalloc.md](regalloc.md). Snail's chooser and constant sections are in
`snail-mail/tools/match/c2/global-allocation.md`.

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

*Verified:* in set_snail_weapon every `push imm`, every `mov target, 0/1` into a candidate, every `mov flag, 0/1`,
the switch's `sub eax, 0` and `cmp any_channel_changed, 0` were promoted. No tuple in that function was refused.

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

*Verified* (`const_trace.py`, first scoring pass, snail `uniform-channel2-tail-no-channel-ref` lead):

| Value | Uses that save 1 | Loads | Queued benefit |
|---|---|---|---|
| 0 | 6 × `transition_immediate = 0` (`mov [2:#8], 0`) | 1, at the entry (`any_channel_changed = 0`) | 5 |
| 1 | 3 × `transition_immediate = 1` | 1, at the mapping switch head | 2 |
| 2, 3, 4, 8, −1 | none | 1 | −1 |

Every other use of 0 and 1 saved 0: about 25 pushes, the target moves, `mov cl,1`, `sub eax,0` and the final
`cmp any_channel_changed,0`. Both ranges were allowed only ebx (byte-only and live across calls). Every range
that interferes with them is therefore charged `100 × (5 + 2) = 700` on ebx by the chooser (0x10732f7c).

## 4. Why a bool passed to a bool parameter always stores to memory

The flag is a register candidate after `pass_mark_register_candidates` (its operands are kind 1 with the
placeholder home). Three steps then send its stores to memory before scoring. *Verified* with IL dumps
(`const_trace.py --il`) and hooks at 0x10731952 and 0x1072eb81.

1. **Argument widening creates a container.** `legalize_operand_forms` (0x10723155), case `IL_PUSHARG` with the
   esp destination, retypes the argument to a dword. For a kind-1 or kind-2 symbol source, it replaces the symbol
   with `symbol_get_part(sym, dword, 4)` (0x107232b2). For a 1-byte local this creates a 4-byte root that takes
   over the front-end name. The local becomes part `+0` of it.
   - In set_snail_weapon the push becomes `push [1:2004 #9 'transition_immediate' z4]`, and the stores stay
     `mov [1:2001 #8^9+0 z1], imm`.
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
   - All nine `#8` stores and all six `#9` reloads in front of the pushes are demoted this way (the hook log
     lists each one).

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

Checks of the rule:
- **set_snail_weapon lead:** prediction 5 and 2. Observed 5 and 2.
- **SetJetPack (snail `set_snail_jetpack`, byte-exact):** the same `bool immediate` pattern, with one `= 1`
  store and one `= 0` store. Prediction 1 − 1 = 0 for both values. Observed 0 and 0, with both stores logged as
  demoted. Nothing competes for ebx there, so it matches.
- **char flag variant (negative control):** prediction −1 and −1. Observed −1 and −1. The flag is in `al`, with
  `setne` at each push.

## 5. set_snail_weapon (snail-mail) walkthrough

The lead (channel 0 without the `Weapon&` borrow, channel 2 with a shared `if (changed) Play(25)`) differs from
native only in two registers: target1 is ebx and the channel-0 case pointers are ebp, where native has the
reverse. The priority-36 case pointers (lr 18/19) are coloured after `this`, target0 and the channel-1/2
pointers. They are coloured before target1 (priority 8), with allowed {ebx, ebp} and costs ebx +700, ebp 0.

Diagnostics. Each one patches allocator state inside the observer. The harness then reports "Observation
changed the whole COFF object", and the observed object is scored with the snail matcher. These are
interventions, not traces. The intervention scripts are not kept in the repo; `scripts/c2/const_trace.py`
reproduces the observations they patch.

| Intervention | Result |
|---|---|
| none (lead) | 41.00% (the matcher also loses the byte lookup table) |
| benefit of constants 0 and 1 set to −1 at the initial queue | **100%, body byte-exact** |
| the same with 0 | **100%, byte-exact** |
| the same with 1 | lead (unchanged) |
| only constant 1 set to −1, or only constant 0 | lead (unchanged). Both must be ≤ 0, as the chooser rule predicts. |
| clear the container's partial-write mark (`#9+5 &= 0x7f` before 0x10727bd3) | constants go to −1 and −1, but the flag gets eax (34%) |
| clear the mark and force the three flag webs to benefit −100 | **100%, byte-exact** |
| set the flag part's class to 3 before promotion (so its writes do not mark the root) | same as clearing the mark: −1 and −1, flag in eax |

So the lead is native except for the positive benefit of constants 0 and 1. No other hidden allocator input
differs. Native's allocation needs benefit(0) ≤ 0 and benefit(1) ≤ 0 when the case pointers are chosen. For
example, the flag could be a candidate whose writes are not marked partial and whose webs are unprofitable, so
it stays in memory.

Source search. None of these reproduces native's registers while keeping native's flag code:
- a 216-variant grid (`constant-candidates/gen.py`): any_channel_changed initialised at the top, at the
  declaration or after the switch; function-level or channel-scoped flag; reused, direct or scoped
  `selected_state`; switch or if/else for the reverse and target dispatch; shared or returning channel-2 tail;
  the reset before or inside the `if`;
- targeted forms: the flag as `int`, `char` or `unsigned char`; `true`/`false`; `register`; `volatile`; a
  pointer or reference alias; the zero store before the call; `Weapon&` borrows at six positions; three
  inline-helper factorings.
- One of those inline helpers is reached through `this` and reproduces the lead exactly (40.54%). Its inlined
  `bool` is class 4 like any local and is demoted the same way (traced benefits 5 and 2).

The char, unsigned char and int forms give native's registers only by putting the flag in a register.

## 6. Tool

```sh
# from snail-mail (uses snail's trace adapter); from crimson it uses crimson's harness
uv run python /Users/banteg/dev/banteg/crimson/scripts/c2/const_trace.py <scratch> --out <new dir> [--il]
```

The tool prints, per value:
- promotions and refusals;
- the uses that save 1 and the loads in the first scoring pass, and the benefit the range was queued with;
- a count of later rescoring events.

It also lists every block-end demotion. `--il` dumps the IL at the stock pass boundaries, entering
`build_live_ranges` and entering the global colourer. The run is fully preserving (whole-COFF, replay and
missing-stream checks).

## 7. Open questions

- Which source gives native set_snail_weapon constants 0 and 1 a non-positive benefit and still keeps the
  flag's code? The interventions narrow this to the flag's IL. Either its stores are not memory at scoring, or
  it has no more counted stores than loads. If its stores are register moves, the flag webs (benefit 10 in the
  mark-cleared and class-3 runs) must still end up in memory. A class-3 writer alone is not enough: the class-3
  intervention puts the flag in eax. Inline-expanded locals are class 4 anyway. Untested: forms where a counted
  store is created only after allocation.
- 0x1072e5b9 (join loads) was not decoded. In every trace here each value got exactly one load.
