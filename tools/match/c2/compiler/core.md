# C2.DLL core IL data model and infrastructure

Scope: the node/tuple model, the IL opcode space, symbols, the CFG, allocators and the
per-function driver of the MSVC 6 back end (`C2.DLL` 12.00.8966, image base 0x10700000).
Names match [`c2_symbols.json`](../../../../analysis/binary_ninja/c2/c2_symbols.json). Confidence is high unless marked otherwise.

## 1. Memory

- **Arenas.** There are 16 arenas at `g_arenas` 0x1079f500, 12 bytes each: {page list, cursor, remaining}.
  `arena_alloc(arena, size)` 0x10701011 rounds the size up to 4. It carves from 0xff8-byte pages
  (the free-page list is 0x1079f4f8) and zero-fills the memory. Requests over 0xff8 bytes get their own `malloc` block.
  `arena_reset(arena)` 0x1070332b frees everything in one arena and clears that arena's bitset free lists.
  Arena usage seen in the code: 1 = per-function data (the function context, fe symbols, symbol chunks);
  4 = reach sets and loop scratch; 0xc = CFG; 0xd/0xe = CSE; 0xf = dominators.
  `function_cleanup` 0x1073fbdd resets arenas 5, 0xc, 8, 1, 6 and 4 after each function.
- **Nodes.** `node_alloc(kind)` 0x10701a7a takes its size from `g_node_kind_sizes` 0x107a0180.
  It reuses nodes from per-size free lists (`g_node_free_lists` 0x10799338, indexed by byte size) or falls back to arena 1.
  `node_free` 0x10701c76 is recursive and dispatches on kind (see §2). `node_clone` 0x10701ef1 makes a deep copy.
- **Operand ownership.** An operand linked into a tuple has bit 0x10 set in +0x10.
  Every constructor and every `tuple_append_*` helper clones an operand that already has this bit
  (`operand_claim` 0x107062a5). A node therefore sits in exactly one list.

## 2. Node kinds (byte at +8)

Every node starts with the common header {+0 next, +4 opcode (dword), +8 kind (byte), +9 flags, +0xa u16 type}.
The type code's high nibble is the class: 1 signed int, 2 unsigned, 3 pointer, 4 float, 5 aggregate, 6 effect, 8 flags.
The low 12 bits are the size in bytes (0x1004 = int32, 0x3004 = pointer, 0x4008 = double).
Code tests kind sets with `1<<kind` masks: 0xffe = operand (1..11), 0x6 = kinds 1/2, 0x60 = kinds 5/6, 0x380 = constants 7..9.

| kind | size | name | constructor | layout / notes |
|---|---|---|---|---|
| 0 | 0xc | header only | – | never allocated |
| 1 | 0x1c | register/temp operand | `operand_new_reg` 0x10702b1e, `operand_new_temp` 0x10702add, `operand_new_hardreg` 0x10723976 | op 0x149; +0x14 symbol; +0x18 storage symbol (the temp itself, then a hard-register symbol after allocation) |
| 2 | 0x1c | memory symbol | `operand_new_sym` 0x10701ca6 | op from `g_symclass_operand_op`[sym class] (0x14a/0x14b); +0x14 symbol |
| 3 | 0x1c | address of symbol | `operand_new_symaddr` 0x1071d9b0 | op 0x14a/0x14b, type = `g_ptr_type` |
| 4 | 0x1c | code address | `operand_new_labelref` 0x107038fa, `operand_new_codeaddr` 0x10760a96 | 0x154 label (+0x14 = label fe symbol); 0x153 function (e.g. `__chkesp`) |
| 5 | 0x30 | address expression (LEA source) | `operand_new_addr` 0x10726cd5 | same layout as kind 6 without the alias class |
| 6 | 0x30 | memory reference | `operand_new_mem` 0x1070148f | op = addressing form; +0x1c alias class; +0x20 direct symbol; +0x24 disp; +0x28 base operand; +0x2c index operand; +0x10 low nibble = scale |
| 7 | 0x20 | integer constant | `operand_new_intconst` 0x10701cc7 | op 0x146; 64-bit value at +0x18/+0x1c, sign- or zero-extended to the type |
| 8 | 0x18 | constant, op 0x147 | – | treated like 0x146 by the allocator; exact meaning unknown |
| 9 | 0x18 | float constant | `operand_new_fconst` 0x1070f018 | op 0x148; +0x14 value/handle |
| 0xa | 0x18 | symbol-id set | `operand_new_regset` 0x1072e1eb | op 0x158; +0x14 bitset of symbol ids (call clobbers) |
| 0xb | 0x18 | memory effect | `operand_new_memeffect` 0x1071dad3 | op 0x159, type 0x6000; +0x14 alias class |
| 0xc | 0x20 | generic tuple | `tuple_new` 0x10702b46, `tuple_new_binary` 0x10723a32, `tuple_new_unary_temp` 0x10701330, `tuple_new_binary_temp` 0x1070fac4, `tuple_new_compare` 0x10707a48 | +0xc prev, +0x10 u16 line, +0x14 aux, +0x18 src list, +0x1c dst list |
| 0xd | 0x20 | block move/copy | `tuple_new_blockop` 0x10751ca0 | ops 0x16a/0x16b |
| 0xe | 0x28 | call | `tuple_new_call` 0x1077e8c3 | +0x24 call info; treated as a side effect |
| 0xf | 0x20 | exit | `tuple_new_exit` 0x1071d58f | 0x16c return value; machine `ret` (op 8) |
| 0x10 | 0x24 | three-operand tuple | `tuple_new_ternary_temp` 0x1071dd94 | fresh temp dst, two sources, +0x20; used for op 0x18f |
| 0x11 | 0x24 | branch | `tuple_new_branch` 0x10703aa7 | src list = [label ref, condition operand]; +0xa holds the condition code; +0x20 is a list of kind-0x1e cells (non-null means conditional). Ops 0x187..0x18c set flags bit 3 |
| 0x12 | 0x28 | intrinsic | `tuple_new_intrinsic` 0x10756629 | dst plus up to 4 sources; +0x20 intrinsic id (descriptor 0x1079bdb8 + id*16, byte +0xc bit 0x20 = pure) |
| 0x13 | 0x2c | switch | `tuple_new_switch` 0x1074f3da | src = selector; +0x20 default label; +0x24 case cells; +0x28 flags. Op 0x18d (0x18e does not add a default reference) |
| 0x14 | 0x24 | pseudo | `tuple_new_pseudo` 0x1070fc19 | EH/state/register-use ops 0x192..0x1ac, 0x19e; +0x20 extra (0x1ab list, 0x1a0 record) |
| 0x15 | 0x24 | pseudo | `tuple_new_kind15` 0x1077ea50 | only op 0x191 seen |
| 0x16 | 0x1c | marker | `tuple_new_marker` 0x107053c4 | no operands; ops 0x1b4..0x1bc; +0x14 payload |
| 0x17 | 0x1c | function entry | `tuple_new_func_entry` 0x1071be1c | op 0x1b0; +0x14 arg; +0x18 list |
| 0x18 | 0x18 | function exit | `tuple_new_func_exit` 0x10717deb | op 0x1b1 |
| 0x19 | 0x18 | block boundary | `tuple_new_block_boundary` 0x107038c0 | op 0x1af; +0x14 block |
| 0x1a | 0x24 | label | `tuple_new_label` 0x10704be6 | op 0x1ae; +0x14 block; +0x18 label fe symbol (sym +0x32 points back); +0x1c reference cells |
| 0x1b | 0x20 | set marker | `new_split_marker` 0x1072044c | op 0x1b2; +0x14 bitset (allocator region) |
| 0x1c | 0x14 | label reference cell | `label_add_ref` 0x107038d5 | {next, ..., +0xc referencing branch/case}; the label symbol's +0x3a refcount is kept in step |
| 0x1d | 0x1c | switch case cell | `switch_add_case` 0x1074f4a3 | +0xc value, +0x10, +0x14 target label, +0x18 owning switch |
| 0x1e | 0x10 | list cell | `tuple_push_cell20` 0x10707b50 | +0xc value |

**Tuple flags (+9).** Bit 0 means the tuple has operand lists (a "real" tuple). Bit 1 means the label is
referenced by the reader. Bit 3 marks the EH and no-return branches 0x187..0x18c ([branch-variants.md](branch-variants.md)). Operand byte +0x10 bit 0x20 marks the base/index of a
memory operand. Operand byte +0x11 bit 0x20 means the base/index are not duplicated in the src list.
The high nibble of +0x11 on a compare's destination holds the relation (1..6).

**Memory sub-operands.** The base and index of a kind-5/6 operand are normally also linked as separate entries
in the tuple's src list, so they count as uses. `tuple_link_mem_subops` 0x10701e5b adds them;
`tuple_remove_mem_subops` 0x10702965 and `node_free` remove them.

**Labels.** A branch's label-ref operand points to the label fe symbol (+0x14). The symbol's +0x32 points to the
label tuple, and the tuple's +0x1c lists the referrers. `label_remove_ref` 0x10703959 and `tuple_retarget`
0x1070429b keep all three in step.

## 3. Opcode space (dword at +4)

- **0x000..0x144** are x86 machine ops. The listing mnemonics are at 0x107a5a90 (enum `c2_opcode`, which also holds the IL ops) and the
  per-op flags at `g_x86_op_flags` 0x107a0494.
- **0x145..0x159** are operand and addressing opcodes (see §2). 0x145 is also the "deleted / no-op" tuple op.
  The addressing forms are:

  | op | form |
  |---|---|
  | 0x14c | [base+disp] |
  | 0x14d | [base+index*s+disp] |
  | 0x14e | [sym+index*s+disp] |
  | 0x14f | [index*s+disp] |
  | 0x150 | [sym+disp] |

  0x151 and 0x152 are unknown.
- **0x15a and up** are IL tuple ops. Sources: the reader switch in `il_read_tree` 0x10714b7f and the integer
  lowering `lower_int_tuple` 0x10729c3c (a switch on op-0x15a through byte table 0x1072be0c).

| op | name | evidence |
|---|---|---|
| 0x15a | PUSHARG | lowering sets dst = ESP and adds ESP as a use |
| 0x15b | ASSIGN | reader stores; lowered to `mov` |
| 0x15d | LOAD (indirect) | lowered to `mov` |
| 0x15e | MOVE_15E | lowered to `mov`; exact role unknown |
| 0x15f | CONVERT | `convert_operand` 0x10710180; lowered to movzx/movsx/and |
| 0x160 | NOT | reader unary; `not` |
| 0x161 | NEG | reader unary; `neg` |
| 0x162 | FROUND | float precision/round (reader case 0x3c); medium confidence |
| 0x163 | LOADCONST | register ← constant (allocator); medium |
| 0x164 | SPILLSTORE | symbol ← register (color.c); medium |
| 0x166 | MODPOW2 | produced by MOD lowering; low |
| 0x16a / 0x16b | BLOCKMOVE / BLOCKCOPY | expanded in cgintrin 0x10756732 |
| 0x16c | RETVAL | moved into EAX (or a subregister); a 0x19e use is added |
| 0x16d | ADD | `add` |
| 0x16e | SUB | `sub` |
| 0x16f | MUL | `imul`, or `shl` for powers of two |
| 0x170 | MULWIDE | one-operand `mul`/`imul` via EAX |
| 0x171 | SHL | |
| 0x172 | AND | |
| 0x173 | OR | |
| 0x174 | XOR | |
| 0x175 | DIV | `div`/`idiv`, or `sar`/`shr` sequences for powers of two |
| 0x176 | MOD | |
| 0x177 | SHR | `sar` or `shr` depending on signedness |
| 0x179..0x17c | loop-opt variants of add/sub/mul/convert | `map_iv_update_opcode` 0x10753f2e; low |
| 0x17d | CMP | result is a flags temp (type 0x8000, storage `g_flags_reg_symbol` 0x107adcd8) |
| 0x17e..0x183 | compare-branch group | `is_compare_branch_op`; meaning unknown |
| 0x184 | CALL | |
| 0x185 | CJUMP | lowered to `jcc`; the condition is in the type field, remapped for unsigned via 0x107a02e8 |
| 0x186 | JUMP | lowered to `jmp` |
| 0x187..0x18c | EH and no-return branches | 0x187 catch return, 0x188/0x189 `__finally` call/return, 0x18a unused, 0x18b exception edge, 0x18c no-return exit; see [branch-variants.md](branch-variants.md) |
| 0x18d | SWITCH | small switches become compare chains (`lower_switch_chain` 0x1074f970) |
| 0x18f | unknown | kind 0x10 |
| 0x190 | INTRINSIC | memset/memcpy/atan2 and similar |
| 0x191 | unknown | kind 0x15 |
| 0x192..0x1a6 | EH ops (ehgen.c) | 0x192 and 0x1a4 raise try depth; 0x194 and 0x196 lower it; 0x1a5 lowers it conditionally (`cfg_build_blocks`) |
| 0x19e | REGUSE | keeps a register live, e.g. EAX before `ret` |
| 0x1a7 | RETURN | replaced by `ret 0` |
| 0x1a8 | EH_STATE | C++ EH state store into EH record +8 (`insert_eh_state_store` 0x107606d5) |
| 0x1ab / 0x1ac | EH unwind-related lists | low |
| 0x1ad | MOVE | lowered to `mov` |
| 0x1ae | LABEL | |
| 0x1af | BLOCK | block boundary |
| 0x1b0 / 0x1b1 | function entry / exit | |
| 0x1b2 | set marker | |
| 0x1b4 / 0x1b5 | prolog end / epilog begin | inserted by `insert_prolog_epilog_markers` 0x107054a4 |
| 0x1b6 / 0x1b7 | debug (-Zi) versions of 0x1b4 / 0x1b5 | |
| 0x1bc | placeholder left when a label is removed | |

`is_commutative_opcode` 0x107062ef covers ops 0x16d..0x17f through a byte table.
`node_has_side_effects` 0x10702f99 shows the per-kind effect classes: kinds 0xe/0xf/0x11/0x13/0x15 always have
effects; kind 0x12 depends on the intrinsic's purity; kind 0x14 op 0x1a8 depends on /EH.

## 4. Symbols

There are two record families.

1. **Front-end symbols** (`c2_fe_symbol`, packed, variable size) are read from the `sym il` / `glo il` streams.
   `fe_symbol_alloc(cls, arena)` 0x107010ea takes the size from `fe_symbol_size` 0x10701117:

   | class | size | meaning |
   |---|---|---|
   | 1 | 0x40 | variable |
   | 3 | 0x43 | label |
   | 4 | 0x4f | external name |
   | 9 | 0x56 | unknown |
   | 11 | 0x40 | unknown |
   | 14 | 0x7b | function |
   | 16 | 0x53 | unknown |
   | 2, 5, 7, 8 | 0x46 | unknown |

   Records are hashed by id (+0x28 & 0x3ff) into the global scope 0x1079a1d8 or the function scope
   (`g_cur_scope` 0x1079a1cc; `fe_symbol_lookup_id` 0x10740f64). External names are hashed separately
   (`fe_symbol_lookup_name` 0x10751056, 128 slots at 0x1079ba18).
   Common fields: +4 class, +8 cached storage symbol, +0xc frame offset, +0x10 size, +0x14 flags, +0x18 name,
   +0x28 id, +0x30/+0x31 subkind/flags, +0x36 storage-class bits.
   Labels add +0x32 (label tuple) and +0x3a (reference count).
   Functions (class 14) add +0x4f exp-IL offset, +0x53 sym-IL offset, +0x57 per-function info,
   +0x6f next function, +0x73 flags. The +0x73 flags are: bit 0 = read from the PCH streams, bit 1 = compiled,
   bit 5 = has a body, 0x300 = EH, copied to ctx +0x34 as 0x18000. +0x14 bit 0x1000 selects the EH setup path.
2. **Storage symbols** (`c2_symbol`, 0x54 bytes) are what operands point at. `symbol_alloc(cls)` 0x107017eb uses
   per-class pools: class 3/6 recycle through 0x1079bc60; class 4/5 through 0x1079bc84, with the live-id bitset
   at 0x1079bc80. The record lives in 32-entry chunks (`symbol_chunk_new` 0x107079c3; chunk list 0x1079bc50;
   chunk index 0x1079bc58). The global id +0x1c maps back to the record through `symbol_by_id` 0x10706fc9, and the
   same id is the bit index in every symbol bitset.
   Fields: +0 fe symbol; +4 class (1 register, 3 temp, 4 local, 5 param, 12 alias group, 13 constant ...);
   +5..+7 flags; +8 parent storage (self for a primary); +0xc next part of the parent; +0x10 type;
   +0x14 defining tuple; +0x1c id; +0x20 size; +0x24 offset (both in bits for registers); +0x28 free-list link;
   +0x34 CSE list; +0x50 use list.
   The hard registers are static symbols at `g_reg_symbols` 0x107ac730 + n*0x54
   (1 EAX .. 8 EDI, class 1, 32 bits), followed by sub-registers.
   `symbol_get_part` 0x10703ba0 finds or creates a field/sub-register part;
   `reg_find_subreg` 0x1072386a does the register case.
   `fe_symbol_get_storage` 0x1071db20 creates the storage symbol for a front-end symbol and caches it at fe +8.
   The storage class depends on the fe class and the +0x36 bits.

## 5. Function context, CFG, blocks, edges

- **Function context** (`c2_function`, 0x40, arena 1, created by `read_function_il` 0x1071ba73):
  +0 function fe symbol, +8 CFG, +0xc loop tree, +0x10 scope hash (0x1004 bytes), +0x24 base line, +0x34 flags.
  The +0x34 flags are: 0x8 = float seen, 0x800 = disables /Og, 0x8000/0x10000 = EH.
  Global pointers: `g_cur_function` 0x107ac380 and `g_cur_func_sym` 0x107ac378.
- **CFG header** (0x34, `cfg_new` 0x10704d25): {first, last, rpo_last (+8), rpo_first (+0xc), arena,
  block size 0x7c, edge size 0x14, block free list, edge free list}.
- **Block** (0x7c):

  | offset | field |
  |---|---|
  | +0 / +4 | physical next / prev |
  | +8 | predecessor edges |
  | +0xc | successor edges |
  | +0x10 / +0x14 | RPO prev / next (DFS parent and iterator while walking) |
  | +0x18 | flags (bit 0 visited; 0x1000000 = ends in a catch return, op 0x187) |
  | +0x1c | head (kind-0x19 boundary tuple) |
  | +0x20 | end (the next block's boundary, exclusive) |
  | +0x60 | dominator bitvector |
  | +0x64 | "reached-from" bitvector |
  | +0x68 | loop |
  | +0x6c | s16 index |
  | +0x6e | loop depth |
  | +0x70 | EH try depth |

  A block's tuples are `head->next` up to `end`.
- **Edge** (0x14): {+0 next successor, +4 next predecessor, +8 from, +0xc to, +0x10 info}.
  `cfg_add_edge(fn, from, to)` 0x10704249 and `cfg_remove_edge` 0x107046b8 maintain them.
- **Building the CFG.** `cfg_rebuild` 0x1070592f runs these steps:
  1. `cfg_reset_single_block` removes every boundary and recreates one block.
  2. Label cleanup: `coalesce_label_runs` and `remove_dead_labels`.
  3. `cfg_build_blocks` 0x10704ed6 splits at labels, after branches and after functions.
     It inserts boundaries with `block_split_before` 0x107041fb and computes the EH depth.
  4. `cfg_build_edges` 0x10705161 adds edges and fixes switch tables.
- **Analysis.** `optimize_flow_graph_initial` 0x107053de and `cfg_reanalyze` 0x10706210 run: prolog/epilog markers, DFS
  (`cfg_dfs_rpo` 0x1070448f), optional RPO relayout (0x10712d16), numbering (0x1070451b), dominators
  (0x1070453f, dense bitvectors in arena 0xf) and loops (0x1070540b, then 0x1070471c and 0x107047d7).
  The loop depth at +0x6e is filled in the loop code. Its consumers are the register allocator's block weights (see [regalloc.md](regalloc.md)).

## 6. Bitsets

- **Sparse bitset** (`c2_bitset`): {first chunk, arena byte}. Chunks are {base (multiple of 32), next, 32 bits}
  in ascending order, handed out four at a time from per-arena free lists (0x107ac420/0x107ac460).
  API: `bitset_new` 0x107017ba, `bitset_set` 0x10701977, `bitset_test` 0x1070251d, `bitset_clear` 0x107026a6,
  `or` 0x1070222d, `and` 0x10702545, `andnot` 0x107024b1, `copy` 0x10702461, `clone` 0x10701400,
  `equal` 0x107022f7, `iter_next` 0x1070260e, `free` 0x107023b9.
  `bitset_iter_next` keeps global iterator state, so it is not reentrant.
- **Dense bitvector** (`c2_bitvec`): {words, arena, nbits (24 bits)}.
  API: `bitvec_new` 0x107042f7, `set` 0x10704386, `test` 0x1070349b, `or` 0x1070439f, `and` 0x107046ef,
  `copy` 0x10704684, `equal` 0x107043cc.

## 7. Flow of one compile

1. `_InvokeCompilerPass@12` 0x10757444 wraps `backend_main` 0x10757541 in SEH. `backend_main`:
   1. Reads the options (including `MSC_CMD_FLAGS`).
   2. Opens `<il>` + "init il" and "glo il" (`open_il_file` 0x107579d4).
   3. Reads the glo header (`read_global_il_header` 0x10757a6d: version stamps 0x130xxxx, PCH mode, initial symbol id).
   4. Reads the globals and calls `compile_functions` 0x10757fc2.
2. `compile_functions` opens "exp il" and "sym il". It then walks `g_function_list` 0x107ac6b0 through
   fsym +0x6f, picking functions with +0x73 bit 5 set and bit 1 clear, and sets bit 1.
   For each function it resets state (0x1071b95b) and calls `read_function_il`.
3. `read_function_il` 0x1071ba73:
   1. Allocates the context.
   2. Seeks the sym stream to fsym +0x53 and reads the symbols (0x107418a4).
   3. Seeks the exp stream to fsym +0x4f.
   4. Creates the entry/exit block boundaries and the CFG (`cfg_create`) and the return label (`g_return_label`).
   5. Runs `il_read_tree` 0x10714b7f.

   `il_read_tree` is a stack reader over front-end opcodes that builds tuples with the constructors above.
   Stream primitives: `il_read_byte` 0x1074161e, `il_read_short` 0x10741642, `il_read_long` 0x107417a8.
4. The pass list runs, with `abort_poll` 0x107013f2 between passes (see the pass map in [README.md](README.md)).
   Lowering (`lower_tuple` 0x10729b6e → `lower_int_tuple` / `lower_x87_tuple` 0x10762fc3 / `lower_int64_tuple`
   0x1075ac4f) rewrites the IL op field in place to x86 op numbers. Later passes then run on machine tuples with
   the same node layout.
5. Emission happens, then `function_cleanup` 0x1073fbdd resets the per-function arenas.

## 8. Errors

- `ice_fatal` 0x1076ab12 (fastcall: file, line) → `fatal_error` 0x10796d99(1) (C1001) → `print_diagnostic`
  0x10796ef7 → `abort_compile` 0x1077d598, which raises exception 0xe0005032.
- `warning(level, id, ...)` 0x10742bbe compares against the /W level (0x107ac33c) and a per-warning override
  table (0x1079f424). Warnings become errors under /WX.
- Message text comes from `load_message` 0x10797232.

## Open questions

- Operand kind 8 (op 0x147) and opcodes 0x151, 0x152, 0x155..0x157, 0x165, 0x167..0x169, 0x178, 0x17e..0x183,
  0x18f, 0x191 and most EH ops are unresolved. The branch ops 0x187..0x18c are decoded in [branch-variants.md](branch-variants.md).
- The +0x20 field of the label tuple, the remaining fields of the 0x54 symbol (+0x18, +0x2c..+0x4c), and
  +0x24..+0x5f of the block.
- The front-end class numbering beyond 1/3/4/14 is unknown. The byte at +0x30 of label symbols (checked
  against 0x53/0x56) is also unexplained.
- The IL names for 0x162..0x164 and 0x179..0x17c are inferred from usage and are only medium/low confidence.
