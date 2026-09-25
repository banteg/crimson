/* C2.DLL (VC6 12.00.8966 back end) data structures for Binary Ninja.
   Applied by scripts/binja_c2_apply.py. Offsets are verified against the pinned binary;
   field roles marked by phase are reused by different passes. See tools/match/c2/compiler/README.md. */

typedef enum c2_node_kind : uint8_t {
    NK_NONE = 0x0 /* header only, never allocated */,
    NK_REG = 0x1 /* register/temp operand */,
    NK_SYM = 0x2 /* memory symbol operand */,
    NK_SYMADDR = 0x3 /* address of symbol */,
    NK_CODEADDR = 0x4 /* label/function reference */,
    NK_ADDR = 0x5 /* address expression */,
    NK_MEM = 0x6 /* memory reference */,
    NK_ICONST = 0x7 /* integer constant */,
    NK_CONST8 = 0x8 /* constant (op 0x147) */,
    NK_FCONST = 0x9 /* float constant */,
    NK_REGSET = 0xa /* symbol set operand */,
    NK_MEMEFFECT = 0xb /* memory effect operand */,
    NK_TUPLE = 0xc /* generic tuple */,
    NK_BLOCKOP = 0xd /* block move/copy */,
    NK_CALL = 0xe /* call */,
    NK_EXIT = 0xf /* return value / ret */,
    NK_TUPLE_EXT = 0x10 /* dst,src1,src2,+0x20 */,
    NK_BRANCH = 0x11 /* branch */,
    NK_INTRINSIC = 0x12 /* intrinsic */,
    NK_SWITCH = 0x13 /* switch */,
    NK_PSEUDO = 0x14 /* EH/state/reg-use pseudo */,
    NK_PSEUDO15 = 0x15 /* op 0x191 */,
    NK_MARKER = 0x16 /* marker */,
    NK_FUNC_ENTRY = 0x17 /* function entry 0x1b0 */,
    NK_FUNC_EXIT = 0x18 /* function exit 0x1b1 */,
    NK_BLOCK = 0x19 /* block boundary 0x1af */,
    NK_LABEL = 0x1a /* label 0x1ae */,
    NK_SETMARKER = 0x1b /* 0x1b2 with bitset */,
    NK_LABELREF_CELL = 0x1c /* label reference cell */,
    NK_CASE_CELL = 0x1d /* switch case cell */,
    NK_LIST_CELL = 0x1e /* generic list cell */
} c2_node_kind;

/* Tuple and operand opcodes: x86 machine ops 0..0x144 (listing mnemonics at 0x107a5a90),
   IL and operand ops from 0x145. Lowering rewrites IL ops to machine ops in place. */
typedef enum c2_opcode {
    IL_NOP = 0x145,
    IL_OPND_ICONST = 0x146,
    IL_OPND_CONST8 = 0x147,
    IL_OPND_FCONST = 0x148,
    IL_OPND_REG = 0x149,
    IL_OPND_SYM = 0x14a,
    IL_OPND_SYM2 = 0x14b,
    IL_AM_BASE_DISP = 0x14c,
    IL_AM_BASE_INDEX_DISP = 0x14d,
    IL_AM_SYM_INDEX_DISP = 0x14e,
    IL_AM_INDEX_DISP = 0x14f,
    IL_AM_SYM_DISP = 0x150,
    IL_OPND_FUNC = 0x153,
    IL_OPND_LABEL = 0x154,
    IL_OPND_REGSET = 0x158,
    IL_OPND_MEMEFFECT = 0x159,
    IL_PUSHARG = 0x15a,
    IL_ASSIGN = 0x15b,
    IL_LOAD = 0x15d,
    IL_MOVE_15E = 0x15e,
    IL_CONVERT = 0x15f,
    IL_NOT = 0x160,
    IL_NEG = 0x161,
    IL_FROUND = 0x162,
    IL_LOADCONST = 0x163,
    IL_SPILLSTORE = 0x164,
    IL_MODPOW2 = 0x166,
    IL_BLOCKMOVE = 0x16a,
    IL_BLOCKCOPY = 0x16b,
    IL_RETVAL = 0x16c,
    IL_ADD = 0x16d,
    IL_SUB = 0x16e,
    IL_MUL = 0x16f,
    IL_MULWIDE = 0x170,
    IL_SHL = 0x171,
    IL_AND = 0x172,
    IL_OR = 0x173,
    IL_XOR = 0x174,
    IL_DIV = 0x175,
    IL_MOD = 0x176,
    IL_SHR = 0x177,
    IL_IV_ADD = 0x179,
    IL_IV_SUB = 0x17a,
    IL_IV_MUL = 0x17b,
    IL_IV_CONVERT = 0x17c,
    IL_CMP = 0x17d,
    IL_CALL = 0x184,
    IL_CJUMP = 0x185,
    IL_JUMP = 0x186,
    IL_CATCH_RETURN = 0x187, /* end of a catch block: mov eax, OFFSET continuation; ret */
    IL_FINALLY_CALL = 0x188, /* call $finally */
    IL_FINALLY_RET = 0x189, /* ret ending a __finally block */
    IL_EH_EDGE = 0x18b, /* flow-graph-only exception edge; falls through; deleted in final lowering */
    IL_NORETURN_EXIT = 0x18c, /* after noreturn calls, throw, __assume(0); emits no bytes */
    IL_SWITCH = 0x18d,
    IL_SWITCH_18E = 0x18e,
    IL_OP_18F = 0x18f,
    IL_INTRINSIC = 0x190,
    IL_OP_191 = 0x191,
    IL_EH_TRY_ENTER = 0x192,
    IL_EH_193 = 0x193,
    IL_EH_LEAVE_194 = 0x194,
    IL_EH_LEAVE_196 = 0x196,
    IL_EH_197 = 0x197,
    IL_EH_198 = 0x198,
    IL_EH_199 = 0x199,
    IL_EH_19A = 0x19a,
    IL_EH_19B = 0x19b,
    IL_EH_19C = 0x19c,
    IL_REGUSE = 0x19e,
    IL_EH_1A0 = 0x1a0,
    IL_EH_1A1 = 0x1a1,
    IL_EH_CXX_ENTER = 0x1a4,
    IL_EH_CXX_LEAVE = 0x1a5,
    IL_EH_1A6 = 0x1a6,
    IL_RETURN = 0x1a7,
    IL_EH_STATE = 0x1a8,
    IL_EH_1AB = 0x1ab,
    IL_EH_1AC = 0x1ac,
    IL_MOVE_1AD = 0x1ad,
    IL_LABEL = 0x1ae,
    IL_BLOCK = 0x1af,
    IL_FUNC_ENTRY = 0x1b0,
    IL_FUNC_EXIT = 0x1b1,
    IL_SETMARK = 0x1b2,
    IL_PROLOG_END = 0x1b4,
    IL_EPILOG_BEGIN = 0x1b5,
    IL_PROLOG_END_DBG = 0x1b6,
    IL_EPILOG_BEGIN_DBG = 0x1b7,
    IL_DEAD_LABEL_MARK = 0x1bc,
    X86_P_FIRST = 0x0,
    X86_MOV = 0x1,
    X86_ARPL = 0x2,
    X86_BOUND = 0x3,
    X86_ENTER = 0x4,
    X86_ESC = 0x5,
    X86_IMUL = 0x6,
    X86_INT = 0x7,
    X86_RET = 0x8,
    X86_XCHG = 0x9,
    X86_IN = 0xa,
    X86_OUT = 0xb,
    X86_POP = 0xc,
    X86_PUSH = 0xd,
    X86_CALL = 0xe,
    X86_P_JCC = 0xf,
    X86_JMP = 0x10,
    X86_LDS = 0x11,
    X86_LEA = 0x12,
    X86_LES = 0x13,
    X86_LAR = 0x14,
    X86_LSL = 0x15,
    X86_JCXZ = 0x16,
    X86_LOOP = 0x17,
    X86_LOOPNZ = 0x18,
    X86_LOOPZ = 0x19,
    X86_LGDT = 0x1a,
    X86_LIDT = 0x1b,
    X86_SGDT = 0x1c,
    X86_SIDT = 0x1d,
    X86_DEC = 0x1e,
    X86_DIV = 0x1f,
    X86_IDIV = 0x20,
    X86_INC = 0x21,
    X86_MUL = 0x22,
    X86_NEG = 0x23,
    X86_NOT = 0x24,
    X86_RCL = 0x25,
    X86_RCR = 0x26,
    X86_ROL = 0x27,
    X86_ROR = 0x28,
    X86_SAR = 0x29,
    X86_SHL = 0x2a,
    X86_SHR = 0x2b,
    X86_ADC = 0x2c,
    X86_ADD = 0x2d,
    X86_AND = 0x2e,
    X86_CMP = 0x2f,
    X86_OR = 0x30,
    X86_SBB = 0x31,
    X86_SUB = 0x32,
    X86_TEST = 0x33,
    X86_XOR = 0x34,
    X86_CMPS = 0x35,
    X86_INS = 0x36,
    X86_LODS = 0x37,
    X86_MOVS = 0x38,
    X86_OUTS = 0x39,
    X86_SCAS = 0x3a,
    X86_STOS = 0x3b,
    X86_XLAT = 0x3c,
    X86_LLDT = 0x3d,
    X86_LMSW = 0x3e,
    X86_LTR = 0x3f,
    X86_SLDT = 0x40,
    X86_SMSW = 0x41,
    X86_STR = 0x42,
    X86_VERR = 0x43,
    X86_VERW = 0x44,
    X86_FADD = 0x45,
    X86_FMUL = 0x46,
    X86_FSUB = 0x47,
    X86_FSUBR = 0x48,
    X86_FDIV = 0x49,
    X86_FDIVR = 0x4a,
    X86_FADDP = 0x4b,
    X86_FMULP = 0x4c,
    X86_FSUBP = 0x4d,
    X86_FSUBRP = 0x4e,
    X86_FDIVP = 0x4f,
    X86_FDIVRP = 0x50,
    X86_FIADD = 0x51,
    X86_FICOM = 0x52,
    X86_FICOMP = 0x53,
    X86_FIDIV = 0x54,
    X86_FIDIVR = 0x55,
    X86_FILD = 0x56,
    X86_FIMUL = 0x57,
    X86_FISUB = 0x58,
    X86_FISUBR = 0x59,
    X86_FIST = 0x5a,
    X86_FISTP = 0x5b,
    X86_FCOM = 0x5c,
    X86_FCOMP = 0x5d,
    X86_FCOMPP = 0x5e,
    X86_FXCH = 0x5f,
    X86_FLD = 0x60,
    X86_FFREE = 0x61,
    X86_FST = 0x62,
    X86_FSTP = 0x63,
    X86_FBLD = 0x64,
    X86_FLDCW = 0x65,
    X86_FLDENV = 0x66,
    X86_FRSTOR = 0x67,
    X86_FSAVE = 0x68,
    X86_FBSTP = 0x69,
    X86_FSTCW = 0x6a,
    X86_FSTENV = 0x6b,
    X86_FSTSW = 0x6c,
    X86_FNSTCW = 0x6d,
    X86_FNSTSW = 0x6e,
    X86_FNSAVE = 0x6f,
    X86_FNSTENV = 0x70,
    X86_FNINIT = 0x71,
    X86_FNCLEX = 0x72,
    X86_FNDISI = 0x73,
    X86_FNENI = 0x74,
    X86_F2XM1 = 0x75,
    X86_FABS = 0x76,
    X86_FCHS = 0x77,
    X86_FCLEX = 0x78,
    X86_FDECSTP = 0x79,
    X86_FDISI = 0x7a,
    X86_FENI = 0x7b,
    X86_FINCSTP = 0x7c,
    X86_FINIT = 0x7d,
    X86_P_FLDT = 0x7e,
    X86_FLDZ = 0x7f,
    X86_FLDPI = 0x80,
    X86_FLDL2E = 0x81,
    X86_FLDL2T = 0x82,
    X86_FLDLG2 = 0x83,
    X86_FLDLN2 = 0x84,
    X86_FNOP = 0x85,
    X86_FPATAN = 0x86,
    X86_FPREM = 0x87,
    X86_FPTAN = 0x88,
    X86_FRNDINT = 0x89,
    X86_FSCALE = 0x8a,
    X86_FSETPM = 0x8b,
    X86_FSQRT = 0x8c,
    X86_FTST = 0x8d,
    X86_FWAIT = 0x8e,
    X86_FXAM = 0x8f,
    X86_FXTRACT = 0x90,
    X86_FYL2X = 0x91,
    X86_FYL2XP1 = 0x92,
    X86_P_FSTTP = 0x93,
    X86_FLD1 = 0x94,
    X86_AAA = 0x95,
    X86_AAD = 0x96,
    X86_AAM = 0x97,
    X86_AAS = 0x98,
    X86_CBW = 0x99,
    X86_CLC = 0x9a,
    X86_CLD = 0x9b,
    X86_CLI = 0x9c,
    X86_CLTS = 0x9d,
    X86_CMC = 0x9e,
    X86_CWD = 0x9f,
    X86_DAA = 0xa0,
    X86_DAS = 0xa1,
    X86_HLT = 0xa2,
    X86_P_IMUL3 = 0xa3,
    X86_INTO = 0xa4,
    X86_IRET = 0xa5,
    X86_LAHF = 0xa6,
    X86_LEAVE = 0xa7,
    X86_P_LJCC = 0xa8,
    X86_NOP = 0xa9,
    X86_POPA = 0xaa,
    X86_POPF = 0xab,
    X86_PUSHA = 0xac,
    X86_PUSHF = 0xad,
    X86_SAHF = 0xae,
    X86_P_SEG = 0xaf,
    X86_STC = 0xb0,
    X86_STD = 0xb1,
    X86_STI = 0xb2,
    X86_WAIT = 0xb3,
    X86_P_EMIT = 0xb4,
    X86_REP = 0xb5,
    X86_LOCK = 0xb6,
    X86_REPNZ = 0xb7,
    X86_REPZ = 0xb8,
    X86_P_EPOP = 0xb9,
    X86_P_EPUSH = 0xba,
    X86_P_DATA = 0xbb,
    X86_P_RPUSH = 0xbc,
    X86_P_SCC = 0xbd,
    X86_LSS = 0xbe,
    X86_LFS = 0xbf,
    X86_LGS = 0xc0,
    X86_P_IMUL2 = 0xc1,
    X86_MOVZX = 0xc2,
    X86_P_MOVZXW = 0xc3,
    X86_MOVSX = 0xc4,
    X86_P_MOVSXW = 0xc5,
    X86_P_JMP3216 = 0xc6,
    X86_P_JMP1632 = 0xc7,
    X86_BSF = 0xc8,
    X86_BSR = 0xc9,
    X86_SHLD = 0xca,
    X86_SHRD = 0xcb,
    X86_BT = 0xcc,
    X86_BTS = 0xcd,
    X86_BTR = 0xce,
    X86_BTC = 0xcf,
    X86_P_MOVSR = 0xd0,
    X86_FUCOM = 0xd1,
    X86_FUCOMP = 0xd2,
    X86_FUCOMPP = 0xd3,
    X86_FPREM1 = 0xd4,
    X86_FSINCOS = 0xd5,
    X86_FSIN = 0xd6,
    X86_FCOS = 0xd7,
    X86_BSWAP = 0xd8,
    X86_XADD = 0xd9,
    X86_CMPXCHG = 0xda,
    X86_INVD = 0xdb,
    X86_WBINVD = 0xdc,
    X86_INVLPG = 0xdd,
    X86_CWDE = 0xde,
    X86_CDQ = 0xdf,
    X86_CMPS_E0 = 0xe0,
    X86_LODS_E1 = 0xe1,
    X86_MOVS_E2 = 0xe2,
    X86_OUTS_E3 = 0xe3,
    X86_XLAT_E4 = 0xe4,
    X86_EMMS = 0xe5,
    X86_MOV_E6 = 0xe6,
    X86_PACKSS = 0xe7,
    X86_PACKUSWB = 0xe8,
    X86_PADD = 0xe9,
    X86_PADDS = 0xea,
    X86_PADDUS = 0xeb,
    X86_PAND = 0xec,
    X86_PANDN = 0xed,
    X86_PCMPEQ = 0xee,
    X86_PCMPGT = 0xef,
    X86_PMADDWD = 0xf0,
    X86_PMULHW = 0xf1,
    X86_PMULLW = 0xf2,
    X86_POR = 0xf3,
    X86_PSLL = 0xf4,
    X86_PSRA = 0xf5,
    X86_PSRL = 0xf6,
    X86_PSUB = 0xf7,
    X86_PSUBS = 0xf8,
    X86_PSUBUS = 0xf9,
    X86_PUNPCKH = 0xfa,
    X86_PUNPCKL = 0xfb,
    X86_PXOR = 0xfc,
    X86_CMPXCHG8B = 0xfd,
    X86_CPUID = 0xfe,
    X86_RDMSR = 0xff,
    X86_WRMSR = 0x100,
    X86_RDTSC = 0x101,
    X86_RDPMC = 0x102,
    X86_UD2 = 0x103,
    X86_CMOV = 0x104,
    X86_CMOV16 = 0x105,
    X86_FCMOV = 0x106,
    X86_FCOMI = 0x107,
    X86_FCOMIP = 0x108,
    X86_FUCOMI = 0x109,
    X86_FUCOMIP = 0x10a,
    X86_PAUSE = 0x10b,
    X86_P_LASTP1 = 0x10c,
    X86_P_EFWAIT = 0x10d,
    X86_REP_MOVS = 0x10e,
    X86_REPE_CMPS = 0x10f,
    X86_REPNE_SCAS = 0x110,
    X86_REP_STOS = 0x111,
    X86_REP_LODS = 0x112,
    X86_P_JCC_113 = 0x113,
    X86_JMP_114 = 0x114,
    X86_JMP_115 = 0x115,
    X86_CALL_116 = 0x116,
    X86_RETF = 0x117,
    X86_LDCARRY1 = 0x118,
    X86_LDCARRY = 0x119,
    X86_LDZERO = 0x11a,
    X86_JECXZ = 0x11b,
    X86_SETO = 0x11c,
    X86_SETNO = 0x11d,
    X86_SETB = 0x11e,
    X86_SETAE = 0x11f,
    X86_SETE = 0x120,
    X86_SETNE = 0x121,
    X86_SETBE = 0x122,
    X86_SETA = 0x123,
    X86_SETS = 0x124,
    X86_SETNS = 0x125,
    X86_SETP = 0x126,
    X86_SETNP = 0x127,
    X86_SETL = 0x128,
    X86_SETGE = 0x129,
    X86_SETLE = 0x12a,
    X86_SETG = 0x12b,
    X86_CMOVO = 0x12c,
    X86_CMOVNO = 0x12d,
    X86_CMOVB = 0x12e,
    X86_CMOVAE = 0x12f,
    X86_CMOVE = 0x130,
    X86_CMOVNE = 0x131,
    X86_CMOVBE = 0x132,
    X86_CMOVA = 0x133,
    X86_CMOVS = 0x134,
    X86_CMOVNS = 0x135,
    X86_CMOVP = 0x136,
    X86_CMOVNP = 0x137,
    X86_CMOVL = 0x138,
    X86_CMOVGE = 0x139,
    X86_CMOVLE = 0x13a,
    X86_CMOVG = 0x13b,
    X86_FCMOVB = 0x13c,
    X86_FCMOVE = 0x13d,
    X86_FCMOVBE = 0x13e,
    X86_FCMOVU = 0x13f,
    X86_FCMOVB_140 = 0x140,
    X86_FCMOVNE = 0x141,
    X86_FCMOVNBE = 0x142,
    X86_FCMOVNU = 0x143,
    X86_P_LAST = 0x144
} c2_opcode;

typedef struct c2_node c2_node;
typedef struct c2_operand c2_operand;
typedef struct c2_tuple c2_tuple;
typedef struct c2_symbol c2_symbol;
typedef struct c2_fe_symbol c2_fe_symbol;
typedef struct c2_block c2_block;
typedef struct c2_edge c2_edge;
typedef struct c2_cfg c2_cfg;
typedef struct c2_function c2_function;
typedef struct c2_bitset c2_bitset;
typedef struct c2_bitset_chunk c2_bitset_chunk;
typedef struct c2_bitvec c2_bitvec;

/* Common header of every IL node (operands and tuples). Size 0xc (kind 0). */
struct c2_node {
    c2_node* next;          /* 0x00 list link (operand list or tuple list) */
    c2_opcode opcode;       /* 0x04 x86 op (<0x145) or IL/operand op (>=0x145) */
    c2_node_kind kind;         /* 0x08 c2_node_kind */
    uint8_t flags;          /* 0x09 tuples: bit0 has operand lists, bit1 label referenced, bit3 EH/no-return branch (ops 0x187..0x18c), never threaded, inverted or moved */
    uint16_t type;          /* 0x0a type code: high nibble class (1 int,2 unsigned,3 pointer,4 float,5 aggregate,6 effect,8 flags), low 12 bits size in bytes; branches: condition code */
};

/* Operand kinds 1..4 (0x1c bytes). */
struct c2_operand {
    c2_operand* next;       /* 0x00 */
    c2_opcode opcode;       /* 0x04 0x149 reg, 0x14a/0x14b sym, 0x153 func, 0x154 label */
    c2_node_kind kind;         /* 0x08 */
    uint8_t flags9;         /* 0x09 */
    uint16_t type;          /* 0x0a */
    uint32_t sort_key;      /* 0x0c packed cost / commutative ordering key */
    uint8_t flags10;        /* 0x10 bit0-3 index scale (mem), 0x10 owned by a tuple, 0x20 is base/index of a mem operand, 0x40 volatile, 0x80 misc */
    uint8_t flags11;        /* 0x11 0x08 volatile, 0x20 mem operand base/index not linked in src list; high nibble = relation on 0x17d dst */
    uint16_t pad_12;        /* 0x12 */
    c2_symbol* sym;         /* 0x14 kind1/2/3: symbol; kind4: label or function fe symbol */
    c2_symbol* storage;     /* 0x18 kind1: storage (temp itself, hard register symbol after allocation) */
};

/* Kind 7 integer constant (0x20 bytes). */
typedef struct c2_const_operand {
    c2_operand* next;       /* 0x00 */
    c2_opcode opcode;       /* 0x04 0x146 */
    c2_node_kind kind;         /* 0x08 7 */
    uint8_t flags9;         /* 0x09 */
    uint16_t type;          /* 0x0a */
    uint32_t sort_key;      /* 0x0c */
    uint8_t flags10;        /* 0x10 */
    uint8_t flags11;        /* 0x11 */
    uint16_t pad_12;        /* 0x12 */
    uint32_t field_14;      /* 0x14 */
    uint32_t value_lo;      /* 0x18 value normalized to type (sign/zero extended) */
    uint32_t value_hi;      /* 0x1c */
} c2_const_operand;

/* Kinds 8..0xb (0x18 bytes): fconst (9, op 0x148, +0x14 value), regset (0xa, op 0x158, +0x14 bitset), memeffect (0xb, op 0x159, +0x14 alias class). */
typedef struct c2_small_operand {
    c2_operand* next;       /* 0x00 */
    c2_opcode opcode;       /* 0x04 */
    c2_node_kind kind;         /* 0x08 */
    uint8_t flags9;         /* 0x09 */
    uint16_t type;          /* 0x0a */
    uint32_t sort_key;      /* 0x0c */
    uint8_t flags10;        /* 0x10 */
    uint8_t flags11;        /* 0x11 */
    uint16_t pad_12;        /* 0x12 */
    void* payload;          /* 0x14 */
} c2_small_operand;

/* Kind 5 (address expression, LEA source) and kind 6 (memory reference), 0x30 bytes.
   opcode = addressing form: 0x14c [base+disp], 0x14d [base+index*s+disp], 0x14e [sym+index*s+disp], 0x14f [index*s+disp], 0x150 [sym+disp]. */
typedef struct c2_mem_operand {
    c2_operand* next;       /* 0x00 */
    c2_opcode opcode;       /* 0x04 */
    c2_node_kind kind;         /* 0x08 5 or 6 */
    uint8_t flags9;         /* 0x09 */
    uint16_t type;          /* 0x0a */
    uint32_t sort_key;      /* 0x0c */
    uint8_t flags10;        /* 0x10 low nibble = index scale */
    uint8_t flags11;        /* 0x11 0x20: base/index not linked into the tuple src list */
    uint16_t pad_12;        /* 0x12 */
    c2_symbol* sym;         /* 0x14 */
    uint32_t field_18;      /* 0x18 */
    uint32_t alias_class;   /* 0x1c kind 6 only */
    c2_symbol* base_sym;    /* 0x20 direct symbol (forms 0x14e/0x150) */
    int32_t disp;           /* 0x24 displacement */
    c2_operand* base;       /* 0x28 base operand */
    c2_operand* index;      /* 0x2c index operand */
} c2_mem_operand;

/* Generic tuple (kind 0xc, 0x20 bytes); other tuple kinds extend it. */
struct c2_tuple {
    c2_tuple* next;         /* 0x00 */
    c2_opcode opcode;       /* 0x04 */
    c2_node_kind kind;         /* 0x08 */
    uint8_t flags;          /* 0x09 */
    uint16_t type;          /* 0x0a */
    c2_tuple* prev;         /* 0x0c */
    uint16_t line;          /* 0x10 source line relative to function start */
    uint8_t field_12;       /* 0x12 */
    uint8_t pad_13;         /* 0x13 */
    uint32_t aux;           /* 0x14 kind-specific (CSE value, block for 0x19/0x1a, payload for markers) */
    c2_operand* src;        /* 0x18 source operand list */
    c2_operand* dst;        /* 0x1c destination operand list */
};

/* Kind 0x11 branch (0x24). src list = [label-ref operand, condition operand...]; type = condition code. */
typedef struct c2_branch_tuple {
    c2_tuple base;          /* 0x00 */
    c2_node* cond_cells;    /* 0x20 kind-0x1e cells (e.g. the compare feeding the branch); non-null = conditional */
} c2_branch_tuple;

/* Kind 0xe call (0x28), kind 0x10 (0x24), kind 0x12 intrinsic (0x28), kinds 0x14/0x15 pseudo (0x24). */
typedef struct c2_ext_tuple {
    c2_tuple base;          /* 0x00 */
    uint32_t extra_20;      /* 0x20 intrinsic id (kind 0x12), extra list (0x14/0x15) */
    uint32_t extra_24;      /* 0x24 call info (kind 0xe) */
} c2_ext_tuple;

/* Kind 0x13 switch (0x2c). */
typedef struct c2_switch_tuple {
    c2_tuple base;          /* 0x00 src = selector */
    c2_tuple* default_label;/* 0x20 */
    c2_node* cases;         /* 0x24 kind-0x1d cells */
    uint32_t flags;         /* 0x28 */
} c2_switch_tuple;

/* Kind 0x1d switch case cell (0x1c). */
typedef struct c2_case_cell {
    c2_node* next;          /* 0x00 */
    c2_opcode opcode;       /* 0x04 */
    c2_node_kind kind;         /* 0x08 */
    uint8_t flags;          /* 0x09 */
    uint16_t type;          /* 0x0a */
    int32_t value;          /* 0x0c case value */
    uint32_t field_10;      /* 0x10 */
    c2_tuple* label;        /* 0x14 target label tuple */
    c2_tuple* owner;        /* 0x18 switch tuple */
} c2_case_cell;

/* Kind 0x1a label tuple (0x24). */
typedef struct c2_label_tuple {
    c2_tuple* next;         /* 0x00 */
    c2_opcode opcode;       /* 0x04 0x1ae */
    c2_node_kind kind;         /* 0x08 */
    uint8_t flags;          /* 0x09 */
    uint16_t type;          /* 0x0a */
    c2_tuple* prev;         /* 0x0c */
    uint16_t line;          /* 0x10 */
    uint16_t pad_12;        /* 0x12 */
    c2_block* block;        /* 0x14 */
    c2_fe_symbol* sym;      /* 0x18 label symbol (sym +0x32 points back) */
    c2_node* refs;          /* 0x1c kind-0x1c cells of referencing branches/cases */
    uint32_t field_20;      /* 0x20 */
} c2_label_tuple;

/* Kind 0x19 block boundary (0x18), kinds 0x16..0x18 markers (0x1c), kind 0x1b set marker (0x20). */
typedef struct c2_marker_tuple {
    c2_tuple* next;         /* 0x00 */
    c2_opcode opcode;       /* 0x04 */
    c2_node_kind kind;         /* 0x08 */
    uint8_t flags;          /* 0x09 */
    uint16_t type;          /* 0x0a */
    c2_tuple* prev;         /* 0x0c */
    uint16_t line;          /* 0x10 */
    uint16_t pad_12;        /* 0x12 */
    void* payload;          /* 0x14 block (0x19), bitset (0x1b), arg (0x16..0x18) */
} c2_marker_tuple;

/* Kinds 0x1c (label ref, 0x14) and 0x1e (list cell, 0x10). */
typedef struct c2_ref_cell {
    c2_node* next;          /* 0x00 */
    c2_opcode opcode;       /* 0x04 */
    c2_node_kind kind;         /* 0x08 */
    uint8_t flags;          /* 0x09 */
    uint16_t type;          /* 0x0a */
    void* ref;              /* 0x0c referencing node / value */
} c2_ref_cell;

/* 0x54-byte storage symbol (temps, locals, params, registers ...). */
/* Storage symbol (0x54). Hard registers are symbols too: 0x107ac730 + n*0x54 (1 eax .. 8 edi, then
   sub-registers); for them parent = full register, next_part = narrower alias, size/offset in bits. */
struct c2_symbol {
    c2_fe_symbol* fe;       /* 0x00 front-end symbol (null for compiler temps and registers) */
    uint8_t cls;            /* 0x04 1 register, 3 temp, 4 local, 5 param, 12 alias group, 13 constant ... */
    uint8_t flags5;         /* 0x05 bit0 generated temp */
    uint8_t flags6;         /* 0x06 */
    uint8_t flags7;         /* 0x07 */
    c2_symbol* parent;      /* 0x08 containing storage (self for primary) */
    c2_symbol* next_part;   /* 0x0c next part of the same parent (sub-register / field) */
    uint16_t type;          /* 0x10 */
    uint16_t pad_12;        /* 0x12 */
    c2_tuple* def;          /* 0x14 defining tuple (temps) */
    uint32_t field_18;      /* 0x18 */
    uint32_t id;            /* 0x1c global id: bit index in symbol bitsets, symbol_by_id key */
    int32_t size;           /* 0x20 bytes (bits for register class) */
    int32_t offset;         /* 0x24 offset in parent (bits for registers) */
    int32_t frame_offset;   /* 0x28 locals: frame offset after stack layout; registers: x86 encoding; free-list link while free */
    c2_symbol* frame_next;  /* 0x2c stack layout order list */
    c2_symbol* frame_prev;  /* 0x30 */
    int32_t ref_weight;     /* 0x34 stack layout reference count; registers: constant score; optimizer: CSE list */
    int32_t frame_index;    /* 0x38 */
    uint32_t field_3c;      /* 0x3c */
    c2_bitset* set_40;      /* 0x40 */
    uint32_t field_44;      /* 0x44 */
    uint32_t field_48;      /* 0x48 */
    uint32_t field_4c;      /* 0x4c */
    void* use_list;         /* 0x50 */
};

/* Packed front-end symbol record (sy/glo IL). Common prefix; size depends on class (fe_symbol_size). */
struct __attribute__((packed)) c2_fe_symbol {
    c2_fe_symbol* hash_next;/* 0x00 */
    uint8_t cls;            /* 0x04 1 variable(0x40), 3 label(0x43), 4 external name(0x4f), 9 (0x56), 14 function(0x7b), 16 (0x53) */
    uint8_t flags5;         /* 0x05 */
    uint16_t pad_06;        /* 0x06 */
    c2_symbol* storage;     /* 0x08 cached 0x54 storage symbol */
    int32_t frame_offset;   /* 0x0c */
    int32_t size;           /* 0x10 */
    uint32_t flags14;       /* 0x14 */
    char* name;             /* 0x18 */
    uint32_t field_1c;      /* 0x1c */
    void* owner;            /* 0x20 */
    uint32_t field_24;      /* 0x24 */
    uint32_t id;            /* 0x28 hash key */
    uint32_t field_2c;      /* 0x2c */
    uint8_t subkind;        /* 0x30 */
    uint8_t flags31;        /* 0x31 */
    c2_tuple* label_tuple;  /* 0x32 labels: the label tuple */
    uint32_t storage_flags; /* 0x36 bits 4..6 storage class, 7..10 */
    uint32_t ref_count;     /* 0x3a labels: number of references */
    uint8_t flags3e;        /* 0x3e */
    uint8_t pad_3f;         /* 0x3f */
};

/* Front-end function symbol (class 14, 0x7b bytes). */
typedef struct __attribute__((packed)) c2_fe_function {
    c2_fe_symbol common;    /* 0x00 */
    uint8_t pad_40[0xf];    /* 0x40 */
    uint32_t exp_il_offset; /* 0x4f offset in 'exp il' stream */
    uint32_t sym_il_offset; /* 0x53 offset in 'sym il' stream */
    void* func_info;        /* 0x57 */
    uint8_t pad_5b[0x14];   /* 0x5b */
    c2_fe_symbol* next_function; /* 0x6f function list link (g_function_list) */
    uint32_t func_flags;    /* 0x73 bit0 PCH stream, bit1 compiled, bit5 has body, 0x300 EH bits */
    uint32_t pad_77;        /* 0x77 */
} c2_fe_function;

/* Per-function context (0x40, arena 1). */
struct c2_function {
    c2_fe_symbol* sym;      /* 0x00 */
    uint32_t field_04;      /* 0x04 */
    c2_cfg* cfg;            /* 0x08 */
    void* loops;            /* 0x0c loop tree root */
    void* scope;            /* 0x10 function scope hash table (0x1004 bytes) */
    uint32_t field_14;      /* 0x14 */
    uint32_t field_18;      /* 0x18 */
    uint32_t field_1c;      /* 0x1c */
    uint32_t field_20;      /* 0x20 */
    int32_t base_line;      /* 0x24 */
    uint32_t field_28;      /* 0x28 */
    uint32_t field_2c;      /* 0x2c */
    uint32_t field_30;      /* 0x30 */
    uint32_t flags;         /* 0x34 0x8 uses float, 0x800 disables /Og, 0x10000/0x8000 EH */
    uint32_t field_38;      /* 0x38 */
    uint32_t field_3c;      /* 0x3c */
};

/* CFG header (0x34). */
struct c2_cfg {
    c2_block* first;        /* 0x00 physical order */
    c2_block* last;         /* 0x04 */
    c2_block* rpo_last;     /* 0x08 */
    c2_block* rpo_first;    /* 0x0c */
    uint32_t arena;         /* 0x10 */
    uint32_t block_size;    /* 0x14 0x7c */
    uint32_t edge_size;     /* 0x18 0x14 */
    c2_block* free_blocks;  /* 0x1c */
    c2_edge* free_edges;    /* 0x20 */
    uint32_t field_24;      /* 0x24 */
    uint32_t field_28;      /* 0x28 */
    uint32_t field_2c;      /* 0x2c */
    uint32_t field_30;      /* 0x30 */
};

/* Basic block (0x7c). Tuples of block b: b->head->next .. up to b->end (exclusive). */
struct c2_block {
    c2_block* next;         /* 0x00 */
    c2_block* prev;         /* 0x04 */
    c2_edge* preds;         /* 0x08 linked via edge.next_pred */
    c2_edge* succs;         /* 0x0c linked via edge.next_succ */
    c2_block* rpo_prev;     /* 0x10 also DFS parent while walking */
    c2_block* rpo_next;     /* 0x14 also DFS successor iterator */
    uint32_t flags;         /* 0x18 bit0 visited, 0x1000000 ends in IL_CATCH_RETURN */
    c2_tuple* head;         /* 0x1c block boundary tuple (kind 0x19) */
    c2_tuple* end;          /* 0x20 next block's boundary */
    uint8_t pad_24[0x3c];   /* 0x24 */
    c2_bitvec* dom;         /* 0x60 dominator set */
    c2_bitvec* reach;       /* 0x64 blocks that reach this one */
    void* loop;             /* 0x68 */
    int16_t index;          /* 0x6c */
    uint16_t loop_depth;    /* 0x6e low byte used as depth */
    uint16_t eh_depth;      /* 0x70 try nesting */
    uint8_t pad_72[0xa];    /* 0x72 */
};

/* CFG edge (0x14). */
struct c2_edge {
    c2_edge* next_succ;     /* 0x00 */
    c2_edge* next_pred;     /* 0x04 */
    c2_block* from;         /* 0x08 */
    c2_block* to;           /* 0x0c */
    uint32_t info;          /* 0x10 */
};

/* Sparse bitset: sorted chunk list; header 0xc from per-arena free list. */
struct c2_bitset {
    c2_bitset_chunk* first; /* 0x00 */
    uint8_t arena;          /* 0x04 */
    uint8_t pad_05[3];      /* 0x05 */
    uint32_t field_08;      /* 0x08 top byte preserved */
};

struct c2_bitset_chunk {
    uint32_t base;          /* 0x00 multiple of 32 */
    c2_bitset_chunk* next;  /* 0x04 */
    uint32_t bits;          /* 0x08 */
};

/* Dense bit vector. */
struct c2_bitvec {
    uint32_t* words;        /* 0x00 */
    uint8_t arena;          /* 0x04 */
    uint8_t pad_05[3];      /* 0x05 */
    uint32_t nbits;         /* 0x08 low 24 bits */
};

/* Arena descriptor (16 at 0x1079f500). */
typedef struct c2_arena {
    void* pages;            /* 0x00 */
    uint8_t* cursor;        /* 0x04 */
    int32_t remaining;      /* 0x08 */
} c2_arena;

typedef struct c2_symbol c2_register_descriptor;
typedef struct c2_symbol c2_stack_object;

/* Register allocation (color.c / regasg.c). */
struct c2_register_preference {
    struct c2_register_preference* next;
    c2_register_descriptor* reg;
    int32_t weight;
};

struct c2_live_range {
    struct c2_symbol* symbol;
    uint8_t kind;
    uint8_t flags5;
    uint8_t flags6;
    uint8_t uncharged_stores;
    struct c2_live_range* self;
    int32_t priority;
    c2_register_descriptor* reg;
    struct c2_live_range* next;
    struct c2_live_range* prev;
    uint32_t id;
    struct c2_bitset* allowed;
    int32_t ref_count;
    struct c2_block* first_block;
    struct c2_live_range* hash_next;
    struct c2_block* last_block;
    struct c2_register_preference* prefs;
    struct c2_tuple* def_tuple;
    int32_t benefit;
    uint32_t tie_key;
};

struct c2_candidate_info {
    uint32_t index;
    struct c2_bitset* overlap_set;
    int32_t def_count;
    void* webs;
    struct c2_tuple* def_tuple;
    int32_t current_web;
};

/* Frame layout and exception handling (stack.c / except.c). */
typedef struct c2_stack_slot {
    c2_bitset* members;
    c2_bitset* interference;
    int32_t size;
    int32_t weight;
    int32_t offset;
} c2_stack_slot;

typedef struct c2_stack_slot_member {
    struct c2_stack_slot_member* next;
    void* object;
} c2_stack_slot_member;

typedef struct c2_stack_slot_debug {
    int32_t offset;
    int32_t size;
    c2_stack_slot_member* overlap_members;
    struct c2_stack_slot_debug* next;
} c2_stack_slot_debug;

typedef struct c2_seh_scope_entry {
    int32_t enclosing_level;
    void* filter;
    void* handler;
} c2_seh_scope_entry;

/* Scheduler dependence graph (schedmd.c). */
typedef struct c2_sched_node c2_sched_node;

typedef struct c2_sched_edge {
    struct c2_sched_edge *next_out;   /* 0x00 next in from->out_edges */
    struct c2_sched_edge *next_in;    /* 0x04 next in to->in_edges */
    c2_sched_node *from;              /* 0x08 */
    c2_sched_node *to;                /* 0x0c */
    uint32_t kind;                    /* 0x10 1 RAW reg, 2 WAR reg, 4 WAW reg, 0x20/0x40/0x80 memory, 0x80000 order/barrier */
    uint16_t latency;                 /* 0x14 */
    uint8_t rewrite;                  /* 0x16 low 5 bits: displacement-rewrite kind (bypassable edge) */
    uint8_t pad_17;
} c2_sched_edge;                      /* 0x18 */

struct c2_sched_node {
    c2_sched_node *next;              /* 0x00 */
    c2_sched_node *prev;              /* 0x04 */
    c2_sched_edge *in_edges;          /* 0x08 */
    c2_sched_edge *out_edges;         /* 0x0c */
    c2_sched_node *ready_next;        /* 0x10 */
    c2_sched_node *ready_prev;        /* 0x14 */
    uint32_t pad_18;
    void *tuple;                      /* 0x1c NULL for root/tail sentinels */
    uint16_t preds_left;              /* 0x20 */
    uint16_t out_degree;              /* 0x22 */
    uint16_t bypassable_preds;        /* 0x24 ready when preds_left == bypassable_preds */
    uint16_t pad_26;
    uint32_t priority;                /* 0x28 */
    uint32_t cur_priority;            /* 0x2c ready-list key */
    uint32_t earliest_cycle;          /* 0x30 */
    uint16_t height;                  /* 0x34 */
    uint16_t seq;                     /* 0x36 creation order in window (tie-break) */
    uint8_t latency;                  /* 0x38 */
    uint8_t unit_flags;               /* 0x39 bits0-2 unit class, 0x40 critical path, 0x80 feeds final jcc */
    uint8_t flags;                    /* 0x3a 1 reads mem, 2 writes mem, 4 scheduled, 8 barrier */
    uint8_t pad_3b;
};                                    /* 0x3c */

typedef struct c2_sched_graph {
    c2_sched_node *first;             /* 0x00 root sentinel */
    c2_sched_node *last;              /* 0x04 tail sentinel */
    void *order_head;                 /* 0x08 */
    void *order_tail;                 /* 0x0c */
    uint32_t arena;                   /* 0x10 */
    uint32_t node_size;               /* 0x14 */
    uint32_t edge_size;               /* 0x18 */
    void *free_nodes;                 /* 0x1c */
    void *free_edges;                 /* 0x20 */
    uint32_t node_count;              /* 0x24 */
    uint32_t edge_count;              /* 0x28 */
    uint8_t pad_2c[0xc];
} c2_sched_graph;                     /* 0x38 */
