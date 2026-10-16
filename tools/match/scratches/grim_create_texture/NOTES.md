# grim_create_texture

## Plausibility pass (2026-09-27)

The cached `grim_texture_slot_max_index` local was dropped; the direct compare and store are byte-identical. The source stays exact, byte for byte. See [the Grim audit](../../PLAUSIBILITY-AUDIT-GRIM-2026-09-27.md). Any older description below of the replaced spelling is historical.

The vtable method allocates the first free handle, creates a one-level
render-target texture in the configured D3D format, constructs a 24-byte
`GrimTexture`, marks the D3D texture as owned, stores its dimensions, and
extends the high-water handle when necessary. The native SEH frame is emitted
naturally by `new GrimTexture(name)`. Assigning through the global slot, rather
than retaining a local pointer, reproduces the original repeated slot loads and
all 81 native instructions.

## 1.9.8 code-generation guard

1.9.8 keeps `d3d_texture` in the dead `height` argument slot, so it has no
`push ecx` frame slot. That smaller frame also moves `mov eax, fs:[0]`
ahead of `push -1` and changes the order of the early-return epilogues.
Declaring the texture in a block that ends after its store into the slot's
`GrimTexture` is exact on 1.9.8 under both 8966 and 9044. Without the block,
1.9.93 is exact. 

8966 and 9044 compile every tried spelling to the same code, so no shared
spelling can match both images. Searched without success: the texture
declared first, between `handle`'s declaration and assignment, or after it;
`handle == -1`; an `HRESULT` result local; `FAILED(...)`; a named
`GrimTexture *` local for `new`; an unbraced early return; and the creation
call moved into an inline helper. Any block end from the `->texture` store
to the end of the slot stores gives the same 1.9.8 code.
