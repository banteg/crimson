# grim_texture_load_file

Native target: `grim.dll` at `0x10004ec0..0x1000510f` (591 bytes).

This is an evidence-backed semantic-complete reconstruction, not an exact
match. Microsoft Visual C++ 6.5 with `/O2 /GB /W3 /GR- /GX /MD` produces
exactly 235 normalized instructions against 235 native instructions, with
85.96% similarity, 508.01/591 fuzzy-weighted bytes, and masked references
`24/0/0`.

## Recovered source shape

- The function is `bool GrimTexture::__thiscall(char *path)`. Native receives
  `this` in `ecx`, reads one ANSI path argument, and returns with `ret 4`.
  Correcting the shared declaration from `unsigned short *` to `char *`
  preserves the exact 80-instruction `grim_load_texture_internal` caller.
- A null path returns false. Any existing Direct3D texture is released through
  vtable slot 2, then the object texture field is cleared.
- When the optional lookup blob is loaded, `grim_lookup_blob_find(path)`
  supplies a payload pointer and a one-byte local records whether the lookup
  succeeded. `grim_lookup_blob_size_for_path` at `0x10005b80` performs the
  parallel record walk and returns the matching payload byte count.
- A final `jaz` extension selects the custom path. Lookup-backed JAZ data is
  used in place; disk-backed data is read with `fopen`, `fseek`, `ftell`,
  `new[]`, `fread`, and `fclose`. The native code does not release either the
  file buffer or the decoded image in this function, so the scratch preserves
  those observed leaks.
- The extension predicate is retained separately and initializes the
  branch-owned result byte. This recovers the native 0x30-byte frame, spilled
  lookup-hit byte, path register, texture-slot register, and instruction
  count.
- `grim_decode_jaz_texture` receives the source pointer/size and three output
  pointers. A successful decode stores width and height before calling
  `D3DXCreateTextureFromFileInMemoryEx` with managed-pool/default-size
  arguments. A D3DX failure clears the texture and returns false.
- If the JAZ decoder itself returns null, native leaves the branch result at
  its initial true value. The scratch deliberately preserves this surprising
  success result.
- Non-JAZ lookup payloads use `D3DXCreateTextureFromFileInMemoryEx`; disk paths
  use the 14-argument stdcall wrapper at `0x1000cb9c`. Its file-map setup,
  ANSI-path flag, forwarding call, and `ret 0x38` establish it as
  `D3DXCreateTextureFromFileExA`. Both successful paths copy the returned
  image-info width and height into the texture object.

The live Binary Ninja database now records the loader's `thiscall` prototype,
the lookup-size helper, and `D3DXCreateTextureFromFileExA` with their verified
calling conventions. The name map carries the same evidence.

## Remaining mismatch

Native keeps `path`, `this`, the texture-field address, and lookup data in
`esi`, `ebp`, `ebx`, and `edi`; the retained reconstruction now agrees on
`path` and the texture-field address, but assigns `this` and lookup data to
`edi` and `ebp`. Both spill the lookup-hit byte, use the native 0x30-byte
frame, and emit 235 normalized instructions.

The remaining scheduling delta is localized. Native tests the extension
predicate, loads `grim_lookup_blob_loaded`, and then stores true to the
branch-owned result byte. VC6 stores the known-true predicate byte first and
then loads the global. The non-JAZ branch reloads the global in both versions.
Structured `else` spelling, branch-local snapshots, and explicit
texture-field aliases compile byte-identically. Declaring the global volatile
regresses and still does not recover the schedule, so no unsupported type
qualifier is retained.

The following diagnostic variants were rejected rather than retained:

- `msvc6.5pp` spills the byte and uses the native frame size, but hoists the
  lookup-loaded global across the extension branch and merges more tails.
- Marking the byte `volatile` reaches 79.66%, but adds two real instructions
  and has no semantic basis.
- Giving each branch a separate image-info local prevents tail merging but
  grows the frame to 0x48 because VC6 does not reuse the slots.
- Naming an explicit pointer to the texture-field slot compiles
  byte-identically and does not change the 0x2c frame or register allocation.
- Reversing one width/height assignment prevents tail merging and reaches the
  native instruction count, but emits the wrong store order.
- `/O1`, `/G5`, `/G6`, explicit `this` aliases, named HRESULT temporaries, and
  alternate `if`/`else` spellings either do not resolve the allocation or
  degrade the match.

## Recorded JAZ-result lifetime sweep

`jaz-result-lifetime-mutations.json` records the causal source boundary and 13
ordinary C++ alternatives. Retaining the extension result directly raises the
scratch from 379.38 to 496.49 fuzzy-weighted bytes (64.19% to 84.01%), grows
the candidate from 223 to 234 instructions, recovers the 0x30-byte native
frame, and moves the first mismatch from byte 0 to byte 10.

Separate assignment, declaration order, a named extension result, assignment
in the condition, `!= false`, and double negation are byte-identical to the
retained form. Preinitializing true falls to 82.30%; normalizing through a
ternary falls to 81.95% and adds two instructions. Both the original
branch-local constant and a function-scope assignment inside the branch
collapse to the old 64.19% allocation. The retained direct initialization is
therefore the simplest expression of the native lifetime, without volatile
state or fake storage.

## Recorded lookup-lifetime sweep

Live native disassembly at `0x10004ec0` confirms the first structural
divergence is already present in the prologue: native allocates a 0x30-byte
frame, keeps `path`/`this`/the texture slot/lookup data in
`esi`/`ebp`/`ebx`/`edi`, and spills the lookup-hit byte. The stock candidate
allocates 0x2c bytes, keeps the hit flag in `bl`, and spills `this`.

`lookup-lifetime-mutations.json` records six plausible declaration and
assignment forms against the earlier 64.19% baseline. Reordering the pointer
and flag, moving image outputs before them, splitting their initialization,
spelling the flag as an unsigned byte, and using an explicit conditional all
compiled byte-identically with 223 instructions. An explicit lookup-hit branch
added one instruction and fell to 64.05%. After recovering the result
lifetime, `retained-lookup-order-mutations.json` confirms that putting the
lookup-hit flag before the pointer improves the score from 83.16% to 84.01%,
adds 5.04 fuzzy-weighted bytes and one aligned reference, and is retained.

`object-path-alias-mutations.json` tests the remaining natural persistent
lifetime hypothesis without taking artificial addresses or adding volatile
state. Replayed against the retained result lifetime, all four combinations of
explicit `self` and `source_path` aliases compile byte-identically at 84.01%,
with the same register cycle, 234 instructions, and `23/0/0` references.
Named pointer and reference aliases for the texture-field slot are also
byte-neutral.

## Branch-owned result and register allocation

`jaz-branch-result-mutations.json` separates the extension predicate from the
result used only inside the JAZ branch. Initializing the scoped result from
that predicate is the sole improving variant: it adds 11.52 fuzzy-weighted
bytes, raises the match from 84.01% to **85.96%**, reaches the native
**235/235** instruction count, and improves references from `23/0/0` to
**`24/0/0`**. It also moves the texture-field address from candidate `ebp` to
the native `ebx`, reducing the former three-register cycle to the remaining
`this`/lookup-data swap.

Four follow-up sweeps record 49 ordinary source interactions without finding
a further gain. `object-lookup-allocation-mutations.json` crosses object
aliases with lookup declaration order; all 17 variants are byte-neutral.
`jaz-source-coalescing-mutations.json` tests 23 declaration, assignment, and
file-size materialization combinations for the coalesced
`this -> source_size` and `lookup_data -> source_data` lifetimes; all are
byte-neutral. Five lookup control-flow forms are neutral or regress, and four
JAZ-local snapshots of `grim_lookup_blob_loaded` are byte-neutral. These
results bound lexical ordering and the obvious global-snapshot explanation;
the remaining two-register assignment and one-byte block shift are compiler
allocation residuals.

No volatile state, dummy reference, forced address, fake helper, or
layout-only arithmetic is retained. The residual is a compiler allocation and
tail-placement problem, not unresolved behavior, so the scratch is classified
as semantic-complete with a compiler residual.
