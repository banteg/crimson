# ui_menu_template_pool_init

Native target: `crimsonland.exe` at `0x00417690` (336 bytes).

The compiler-generated initializer constructs twelve adjacent 0xe8-byte UI
template blocks. Each block owns eight 0x1c-byte vertex-like slots, one texture
handle, and a mode sentinel initialized to 4. VC6 emits six direct eight-slot
constructor loops, then six calls to the recovered `invoke_callback_n` vector
constructor helper after reaching its inline-growth budget.

Standard C++ cannot take a constructor's address, although VC6's generated
initializer does exactly that for the vector helper. The scratch therefore
spells the empty constructor callback as an ordinary `construct()` member and
the analysis map records that one explicit lowering alias. This preserves the
same object model and calling convention without assembly, volatile shaping,
or fabricated instructions. All 92 instructions and all 42 static references
then match exactly.

The object now emits the corresponding `effect_vertex_cpp_t::construct` and
`ui_vec2_cpp_t::construct` identities as genuine out-of-line members as well.
Live xrefs to the shared two-instruction implementation at `0x00417a90` come
from `effect_pool_vertices_global_init` at `0x0042de1c` and from
`ui_element_globals_init` at `0x004177f4`, `0x00417825`, and `0x00417a85`.
Each implementation is the same natural `mov eax, ecx; ret` no-op, allowing
VC6 link-time folding without inventing aliases. The configured pool
initializer remains exact.
