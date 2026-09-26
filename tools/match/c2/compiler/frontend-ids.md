# Frontend record ids: which declarations consume them (C1XX 8964 / C2.DLL 8966)

C2 hashes a call's callee by its frontend record id (fe symbol +0x28), see
[call-operand-order.md](call-operand-order.md). This note says where that id comes from and how many ids
each C++ construct consumes, so the id of a function can be predicted from the declarations in front of it.
Addresses are virtual addresses in the pinned C2.DLL (image base 0x10700000). "Verified" means measured
with compiles by the pinned `msvc6.5` driver (C++, `/O2 /G5 /W3`) through
[`scripts/c2/fe_id_probe.py`](../../../../scripts/c2/fe_id_probe.py), or with a preserving trace
(`su_order_trace.py`) and a matcher result. "Read" means static reading only. "Inferred" means a
decomposition that fits all measured totals but was not observed directly.

Short version:

1. **C1XX assigns the ids**, one counter for the whole translation unit. They are written into the
   frontend streams (`gl` for globals, `sy` for function scopes). C2 only reads them.
2. Ids are assigned **eagerly while parsing**, in source order. Unused declarations count, and so do
   unused inline bodies. Uses (calls, references) consume nothing, except when a use makes the compiler
   generate code (implicit special members, template instantiations).
3. A symbol keeps the id of its **first declaration**. Redeclaring a function costs its ids again, but
   does not change its id.
4. Parameters get their ids **before** their function: `int F(int);` takes n (parameter), n+1 (F).
5. Roughly: every declarator is 1 (enumerators, typedef names, members, parameters, variables, locals,
   and the abstract type in a C-style cast). A defined class is 8 plus its members. Every source file
   is 1. Control flow in bodies uses ids for labels. Macros are 0.

## 1. Where the id comes from

| Step | Function | What happens |
|---|---|---|
| Record reader | `p2symtab_10741b6d` 0x10741b6d | Reads one `sym il`/`glo il` record: class byte, then a class-specific layout. Classes 4/0xe/0x10 (external name, function): id, subkind byte, name. Classes 1/2 (variable): a byte, id, a byte, name. Class 3 (label), 7, 8, 9, 0xb: an id each. Class 0x12 (source file): id, name. The id is stored at fe +0x28 (read). |
| Id decoder | `il_read_id` 0x107416cd | Two bytes little-endian; if bit 7 of the second byte is set, four bytes `b0 \| (b1 & 0x7f) << 8 \| (b2 << 16 \| b3 << 24) >> 1` (read; the two-byte form is verified by decoding streams). A different decoder, 0x1079690d, is used when 0x107ac6d4 is set (PCH path; not examined). |
| Hash | `hash_operand` 0x1070db59, kind 4 | `v = fe->id; v>>16 ^ v&0xffff` (call-operand-order.md). |

Verified link between the stream and the hash: in snail's `read_repeating_text_input_key_code` scratch
the stream gives `?RstrASC@@YADD@Z` id 0xfb59. The trace shows the local-argument call key
hash 0xfc02 = 0xfb59 + 0xa9, and the global-argument call 0x0402 = (0xfb59 + 0x8a9) mod 0x10000.
Four more builds at the window edges (section 5) agree the same way.

In an empty translation unit, `int F(int);` gets id 0x109, so the first free id is 0x108. Ids
0x100..0x107 (if the counter starts at 0x100) are used before the first user declaration; what uses
them was not identified.

## 2. Measuring

```sh
# every named record's id in a scratch (the source's directory is searched first)
uv run python scripts/c2/fe_id_probe.py --cflags "/O2 /G5 /W3 /IZ:<include dir>" ids scratch.cpp
# ids consumed by a prefix (a header, or #include lines) placed before int F(int);
uv run python scripts/c2/fe_id_probe.py --cflags "..." measure prefix.h
# F's id after N = 0,1,2,5 copies of each built-in kind (section 3)
uv run python scripts/c2/fe_id_probe.py sweep [--kind enumerator ...]
```

The tool builds `tools/match/c2/capture.c` as a `/B2` wrapper, compiles the probe with the pinned driver,
and scans the captured `gl`/`sy` streams for `<id> <subkind> <name>` (a heuristic scan; decorated names,
locals and parameters decode reliably). A full sweep of the 80 built-in kinds takes about 10 seconds.
`measure` pastes the prefix text into the probe file, so the prefix file itself gets no file record, but
the files it includes do. Evidence names in section 3 that are not sweep kinds (`samename`, `friendfn`,
`inc_*`, `r1`-`r3`) are one-off probes of the same form.

## 3. Ids per construct

All rows are verified by sweeps (N = 0, 1, 2, 5 copies in front of `int F(int);`) or by the one-off
probes named in the evidence column. "First" marks a one-time extra.

### Declarations at namespace scope

| Construct | Ids | Evidence |
|---|---|---|
| `#define`, `#if`, include guards, `#pragma` | 0 | sweep `define` |
| Source file, first time the lexer enters it | 1 | empty header 2 (header + main file), same header again 0, two headers 3, nested 3 files 4 |
| Main file | 1, when it first becomes current again after an include, or at the first function body if nothing is included before | "first body +1" in every body sweep; `body_then_inc` = `inc_then_body` = 4 |
| `enum E { ... };` (named or anonymous) | 1 + 1 per enumerator (explicit values change nothing) | sweeps `enumerator`, `enum_type_1`, `enum_type_empty`; 13762 enumerators = 13763 |
| `typedef` | 1 per declarator name | sweep `typedef`; `typedef struct tag {..} X, *PX` = struct + 2 |
| `typedef struct X {...} X;` (same name as the tag) | 0 for the typedef | `samename` 9 = struct only |
| Redeclared typedef, `extern` variable or forward tag | 0 | sweeps `*_redecl` |
| Function type in any declarator (typedef, variable, member, parameter) | +1 per parameter of that function type | `typedef int (*T)(int, float)` = 3; `int f(int (*cb)(int, int))` = 4 |
| `struct S;` or first elaborated mention `struct S *p` | 1 | sweep `struct_forward` |
| Class definition (struct, class or union, named, nested or anonymous) | 8 + members, see below | `struct S {}` 8, `{ int a; }` 9, anonymous union member 8 + its members |
| Function declaration | 1 + number of parameters | `f()` 1, `f(int)` 2, `f(int, int)` 3, `f(int, int, int, int)` 5 |
| `(void)` parameter list | counts as one parameter: `f(void)` = 2 | sweep `fn_void_void` |
| `...`, default arguments, parameter names, `extern "C"`, `__stdcall`, `inline` | 0 | sweeps `fn_ellipsis`, `fn_default_arg`, `fn_1param_named`, `fn_extern_c_stdcall`, `fn_inline_decl` |
| Each further overload of a name in the same scope | +1 | sweep `fn_overload` 2, then 3 each |
| Redeclaration of a function | full cost again (1 + parameters); the id stays that of the first declaration | `fn_redecl` 2 each; r1-r3 keep 0x109 |
| Function definition | declaration cost + 1 (body) + body contents, even after a prior declaration | `f(int v) {}` 3; declaration + definition 5 |
| Variable declaration or definition (`extern`, `static`, `const`, initialized, array) | 1 per declarator | sweeps `extern_var`, `global_var*` |
| String literal | 1 per distinct text in the TU, at its first occurrence (also in initializers and in unused inline bodies); none in default arguments | `global_string_init` 2; same text in two functions 1 |
| Namespace, `using` declaration, `friend class` | 0 | sweeps `namespace_empty`, `using_decl`; `friend_cls` |
| `friend` function declaration | 1 + parameters | `friendfn` +3 for `friend V operator*(float, const V&)` |
| Function template definition | 2 (one-parameter template function) | sweep `template_fn` |
| Class template definition | 4 (one member and one inline method) | sweep `template_class` |

### Class members

Class base cost is 8. It decomposes (inferred) as tag 1, implicit default constructor 1, implicit
copy constructor 2, one overload link between the two constructors 1, implicit `operator=` 2 and
destructor 1. The rules below reproduce every measured class.

| Member | Ids | Evidence |
|---|---|---|
| Data member, bit-field | 1 per declarator | sweeps `data_member`, `bitfield_member` |
| Static data member | 2; the out-of-class definition `int S::m;` 0 more | sweeps `static_data_member`, `static_member_def` |
| Member function declaration (static, const, operators, conversions) | 1 + parameters | sweeps `method_*`; `op_new` |
| Overloads of one member name | +1 per overload after the first | `mfn_overload` 17 = 9 + 2 + 3 + 3 |
| Constructors | Count the declared ones, plus the implicit copy constructor (2) unless one is declared, plus the implicit default constructor (1) unless any constructor is declared. Then add 1 per constructor after the first. | `S()` 9, `S(int)` 10, `S(const S&)` 7, `Vec(); Vec(float, float)` 16 |
| `operator=` | 2 implicit; a user copy assignment replaces it | `S &operator=(const S&)` 9 |
| Destructor | 1. +4 when it is non-trivial (user-declared, or a member or base has one); +1 more when it is virtual | `~S()` 13, member with `~A()` 13, `virtual ~S()` 17 |
| First virtual function in a class without a polymorphic base | +3 | sweep `virtual_method` 5, then 2 each |
| Class derived from a polymorphic base | +2 (with or without overrides) | `class_derived_polymorphic` 11 |
| Inline body inside the class | +1 (`this`) + 1 (body) + contents | `int m() { return x; }` 3 |
| Out-of-line member definition | 1 + parameters + 1 (`this`) + 1 (body) + contents | sweep `out_of_line_method` 15 = 11 + 4 |
| Nested enum or class | its own cost | `nested_enum` 12 |
| Base clause, access specifiers | 0 | `struct_derived` 9 |

### Function bodies

Inline bodies that are never called give the same counts as emitted bodies (every `stmt_*_inline`
sweep equals its emitted twin), so bodies are numbered at parse time.

| Construct | Ids | Evidence |
|---|---|---|
| Local variable | 1 per declarator (+1 per parameter of a function-pointer type) | sweep `local_var`; `int (*q)(int) = &g` 2 |
| `static` local | 2 | sweep `static_local` |
| C-style cast `(T)x`, `static_cast<T>`, `sizeof(T)` | 1 each (a type-id). Functional `int(x)` and `sizeof x`: 0 | `cast_explicit`, `sizeof_type`; `(int)(unsigned)(char)v` 3 |
| `if` | 1; `else` +1; `\|\|` in the condition +1; `&&` 0 | sweeps `if*` |
| `while`, `do-while` | 3 | sweeps `while`, `do_while` |
| `for` | 3 + its declarations | sweep `for_decl` 4 |
| `switch` | 4 + 1 per `case` + 1 for `default` | empty 4, 1-3 cases 5-7, with default 8 |
| User label | 1 | sweep `user_label` |
| `return`, `break`, `continue`, `goto`, `?:`, value `&&`/`\|\|`/`!`, arithmetic, calls, member access, float constants | 0 | sweeps `expression_stmt`, `call_same_fn`, `stmt_*` |
| Use that generates an implicit member (copy constructor, `operator=`, default constructor, destructor) | a few, at the use | `S x(*p)` +5, `*q = *p` +3 for a class with non-trivial members |
| Template instantiation | at the first use: 5 for a one-parameter function template, about 12 for a small class template | `template_*_instantiated` |

## 4. Estimating a header

1. Prefer measuring. `fe_id_probe.py measure` compiles the header in front of `int F(int);` and
   prints the difference. `ids` prints the id of the real callee in the real scratch.
2. For headers that do not exist yet, count with section 3:
   - 1 per file, plus 1 for the main file after the first include;
   - enums 1 + enumerators; typedefs 1 each, but 0 for a same-name `typedef struct X {} X`;
   - functions 1 + parameters, repeated for every redeclaration and for the definition (+1 body);
   - classes 8 + data members + member functions (1 + parameters each) + overload and
     constructor adjustments + 4 for a non-trivial destructor + 3 for the first virtual + inline bodies
     (2 + contents);
   - macros 0.
3. Checks against real headers (verified): the DirectX 8.1 `d3d8caps.h` (one struct of 53
   declarators) predicts 1 + 8 + 53 + 1 = 63 and measures 63. The `D3DXVECTOR2` class from
   `d3dx8math.h` (inline default constructor, 3 constructors, 16 operators, a friend, 2 members,
   2 typedef names) predicts 50 and measures 50. A mixed C header block (struct, enum, handle, prototype,
   function-pointer typedef and class) predicts 51 and measures 51.

The order of declarations matters only through the callee: what counts is everything before the
callee's **first** declaration. Declarations after it, and ids consumed later by redeclarations or
bodies, only move later callees.

## 5. Snail-mail: RShell's `RstrASC`

Measured ids in the current prelude (`tools/match/include/rshell_prelude.h`, in snail-mail):

| Prefix | `F` id after it | Consumed |
|---|---|---|
| nothing | 0x109 | 0 |
| `<windows.h>` (`<mmsystem.h>` adds 0: already included) | 0xa3ce | 41669 (headers, files and main file) |
| + `d3d8.h` (DirectX 8.1) | 0xabc0 | 2034 |
| + `d3dx8.h` | 0xbd32 | 4466 |
| + `dinput.h` (`DIRECTINPUT_VERSION` 0x0800) | 0xc594 | 2146 |
| The same four as a header file (`rshell_prelude.h` without its stand-in) | 0xc595 | +1 (the prelude file) |
| + the stand-in enum (1 + 13762 enumerators) | 0xfb58 | 13763 |

`RstrASC` is the first declaration in `rstring.h`: file 1 + parameter 1, so its id is 0xfb59.

The call hash puts the key call first when `0xf757 <= id <= 0xff56` (one-variable source,
call-operand-order.md section 4). The edges were checked with the matcher and traced keys, on copies
with the prelude written directly into `scratch.cpp` (one file record fewer):

| Stand-in enumerators (inline prelude) | `RstrASC` id | Keys (key call, global call) | Result |
|---|---|---|---|
| 12735 | 0xf755 | 0xf7fe, 0xfffe | 99.09% |
| 12736 | 0xf756 | 0xf7ff, 0xffff | 99.09% |
| 14783 | 0xff55 | 0xfffe, 0x07fe | 100.00% |
| 14784 | 0xff56 | 0xffff, 0x07ff | 100.00% |

So with `rshell_prelude.h` as a header, RShell's own declarations between `dinput.h` and the first
declaration of `RstrASC` must consume **12,737 to 14,784 ids** (the stand-in is 13,763). Each of
RShell's own header files counts 1 toward that. If the original `RShell.h` included `rstring.h` before
the engine headers, only what precedes that include counts.

For ids from 0x10000 to 0x1ffff the fold is `(id & 0xffff) ^ 1`, so the next window is about
0x1f756..0x1ff57 (the xor swaps the edge ids pairwise). That needs about 65,000 more ids and is not
plausible here.

## 6. Open questions

- What uses ids 0x100..0x107 before the first user declaration.
- The decomposition of the class base cost (8) and of the non-trivial destructor (+4), virtual (+3) and
  polymorphic-base (+2) extras is inferred from totals. The totals are verified.
- C translation units (`.c`) were not measured. There are no implicit class members there, so struct
  costs certainly differ.
- The PCH path (0x107ac6d4 set, decoder 0x1079690d) was not examined.
- Template instantiation and implicit-member generation costs were measured for one shape each.

Frontend ids also reach C2 through address constants: `make_constant_candidate_operand` buckets a
string literal by its frontend id mod 64, and freed constant ranges are reused last-in-first-out,
which can change register-allocation ties ([tu-prelude.md](tu-prelude.md)).
