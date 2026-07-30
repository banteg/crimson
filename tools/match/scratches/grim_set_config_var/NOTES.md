# grim_set_config_var

Native target: `grim.dll` at `0x10006580..0x10006b7e` (1534 bytes).

The native function is a sparse `switch` over configuration IDs `5..85`.
Ordinary IDs copy the complete 16-byte `grim_config_value_t` record. The
specialized routes update callback pointers, owned title and resource-pack
strings, input flags, backbuffer state, the D3D texture/blend/filter states,
the gamma ramp, the optional device window, and the render-disable flag.

The ID mapping, early-return policy, string ownership, gamma formula and
clamps, and D3D calls are recovered from the native switch lookup table,
HLIL, and disassembly. The implementation intentionally keeps the logical
C++ method ABI and uses the normal Direct3D 8 interface; it contains no
inline assembly, padding, volatile state, forced registers, dummy
dependencies, or fake references.

Microsoft Visual C++ 6.5 with `/O2 /GB /W3 /GR-` now produces a `94.36%`
candidate with `443/443` normalized instructions and references `68/1/1`.
The audit identifies the only unresolved/mismatched pair as the compiler's
private sparse-switch lookup and jump tables; all externally meaningful
references resolve. The residual is block placement and shared-tail shaping,
not missing behavior, so the scratch is marked semantic-complete with a
compiler residual.

The available `/GB`, `/G5`, `/G6`, MSVC 6.5, and MSVC 6.5 processor-pack
profiles were checked. `/GB` and `/G5` tie for best; `/G6` and the
processor-pack compiler regress.

## Recorded router-lifetime wave

Live native disassembly shows full scalar record copies in the shared router
tails. `common-copy-tail-mutations.json` evaluated 19 single and pair
spellings. A named config destination followed by four scalar word copies adds
ten candidate instructions and 23.00 fuzzy-weighted bytes, raising the score
from 88.05% to 89.55% without changing the reference audit. The simpler tied
form was retained; the extra source-only value copy was discarded.

The filter route independently exposes native `load current; materialize
config pointer; compare current`. `filter-current-lifetime-mutations.json`
found three byte-identical ways to express that order. The simplest retained
form loads `current` directly before naming the destination pointer. It adds
one instruction, 8.89 fuzzy-weighted bytes, and two resolved references,
bringing the composed result to **90.12%** with a 151.48-byte fuzzy gap.

`resource-path-lifetime-mutations.json` tested four direct-slot and cached
`strdup` call forms against the native import-cache allocation. Three are
byte-neutral and the named-config form regresses, so none was retained. A
five-profile diagnostic matrix likewise keeps stock VC6 `/GB` tied for best;
no compiler override is justified.

## Shared record-copy tail

Raw native disassembly at `0x100065b3..0x100065e8` and
`0x10006b42..0x10006b7e` shows that texture-stage configuration ID 26
publishes word zero and then joins the ordinary router's word-one-through-three
tail. `shared-copy-tail-mutations.json` evaluated all 24 singles and pairs
across that entry and the common destination. Eight natural two-site forms
compile identically and improve the baseline.

The retained negative-test form mirrors the native failure branch, stores word
zero, and enters an explicit shared tail. It adds five previously missing
instructions, **64.92 fuzzy-weighted bytes**, and three exact prefix
instructions. The result is **94.36%**, with an **86.57-byte fuzzy gap**,
exactly **443/443 instructions**, prefix **7/443**, and references
**68/1/1**.

Four follow-up searches bound the remaining local residual. Replaying the
resource-path lifetime menu is byte-neutral. Explicitly spelling the proven
case-16 index before the intervening resource lookup removes three
instructions and regresses by 19.40 weighted bytes. Six scalar source-load
orders and six destination pointer/reference shapes either collapse to the
retained object or regress. The native DLL's imported `_strdup` also motivated
an ABI-profile check: `/MD` reproduces dynamic-CRT call lowering but scores
93.57%, below the canonical `/GB` result, so no flag override is retained.

Two recorded import-spelling matrices test the native case-16 `_strdup`
pointer lifetime directly. `strdup-import-lifetime-mutations.json` evaluates
five declaration and call spellings: the `_strdup` spelling is byte-neutral,
while explicit `dllimport` redeclarations conflict with the CRT headers and
fail compilation. Its SHA-256 is
`f8b49fba0c91e2dd06b3b45e6ed447e6048df96a05514a9850cc62a314c55e4f`.

`strdup-iat-symbol-mutations.json` evaluates three explicit IAT-symbol
combinations. The pointer declaration alone is byte-neutral; routing both
calls through it compiles but regresses by 6.93 fuzzy-weighted bytes, and the
call-only partial form fails compilation. The native import-pointer hoist
cannot be recovered through an honest source-level declaration under the
current CRT headers, so no import spelling is retained. The plan SHA-256 is
`147c5fe7379f0cc416f334900cdb9c37e81ff6002d01909c1c32304571611061`.

## Private switch-table audit

Live bytes identify the final `68/1/1` reference pair precisely. Native has a
23-entry jump table at `0x10006b80..0x10006bdc` followed by the 81-byte
ID-`5..85` lookup table. ID 8 receives dispatch index 3 while the true default
IDs 9 and 10 receive index 22; both jump-table entries point to the same
ordinary record-copy block at `0x10006b42`. The stock candidate emits the same
router body but folds all three IDs into one default index, leaving a 22-entry
private jump table. Thus the unresolved/mismatched operands are the two
compiler-local tables, not program data or a missing case behavior.

Two recorded sweeps bound honest source recovery. Adding explicit `case 8`
(alone or grouped with IDs 9/10) compiles byte-identically because VC6 folds
the labels before table emission. Giving case 8 a separately spelled full-copy
body adds 5 to 15 instructions and still leaves the private-table pair at
`1/1`; the least-bad forced form falls to 93.83%. The canonical 94.36%,
443-instruction source is retained.

The object audit identifies the pair by compiler-local symbol as well as
address. Candidate `$L44367` is the unresolved 81-byte ID lookup table paired
with jump table `$L44368`; live Binary Ninja types the native counterparts at
`0x10006bdc` as `uint8_t[0x51]` and `0x10006b80` as
`uint32_t[0x17]`. This supports a matcher improvement, not a source or header
change: canonicalize a VC6 byte lookup table through its companion jump
targets so semantically equivalent folded dispatch entries audit as
compiler-private. No shared matcher code is changed in this scratch.

## Sparse-switch partition matcher

The shared matcher now implements the bounded compiler-private audit proposed
above. It maps each byte-table index through the companion local jump table,
then canonicalizes destination equivalence classes by first occurrence. The
candidate's 22-entry table and native DLL's 23-entry table produce the same
81-byte partition; the extra native entry aliases the ordinary copy block and
does not change dispatch behavior.

Fresh matching keeps the honest source score at **94.36%**, exactly **443/443
instructions**, and prefix **7/443**, while the reference audit improves from
`68/1/1` to **`70/0/0`**. Unit coverage proves both the COFF table-pair
recognition and linked-image comparison, including an extra duplicate jump
entry with different byte indices. The remaining residual is therefore
instruction-layout/codegen only.

## Dynamic-CRT source interaction audit

The native body imports `_strdup`, so the remaining source menus were replayed
under `/MD` rather than judging the ABI profile from the canonical source
alone. The `/MD` baseline is **93.57%**, **443/443** instructions, prefix
**7/443**, and `refs=70/0/0`, below the retained static-profile **94.36%**.

Three existing menus cover the four case-16 ownership/call lifetimes, six
shared-tail destination forms, and six source-load orders. All 16 variants are
byte-neutral or worse under `/MD`. The new
`md-shared-copy-tail-interactions.json` exhaustively crosses three case-26
entries with aggregate, direct-scalar, and named-scalar generic tails. All
**15/15** variants are worse; the best reaches only **90.02%** and drops the
exact prefix to four instructions.

Across **31** evaluated variants, dynamic-CRT lowering never interacts
profitably with the recovered source shapes. The native import form is real,
but `/MD` cannot recover the remaining block placement and shared-tail
allocation under the available VC6 toolchain.
