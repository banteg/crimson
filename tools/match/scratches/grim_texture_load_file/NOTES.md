# grim_texture_load_file

Native target: `grim.dll` at `0x10004ec0..0x1000510f` (591 bytes).

Microsoft Visual C++ 6.5 with `/O2 /GB /W3 /GR- /GX /MD` now reproduces the
target exactly: **100.00%**, **235/235 instructions**, a 235-instruction exact
prefix, and audited references **`25/0/0`**.

## Recovered source shape

- The function is `bool GrimTexture::__thiscall(char *path)`. Native receives
  `this` in `ecx`, reads one ANSI path argument, and returns with `ret 4`.
- A null path returns false. An existing Direct3D texture is released through
  vtable slot 2 before the object's texture field is cleared.
- When the optional lookup blob is loaded, `grim_lookup_blob_find(path)`
  publishes its payload into one persistent `source_data` owner and a separate
  byte records whether the lookup succeeded.
- A `jaz` extension selects the custom decoder path. Lookup-backed data remains
  in `source_data`; the disk fallback overwrites that same owner with a `new[]`
  buffer filled by `fopen`, `fseek`, `ftell`, `fread`, and `fclose`.
- `grim_decode_jaz_texture` receives `source_data`, its byte count, and width,
  height, and decoded-size outputs. A successful decode publishes dimensions
  before `D3DXCreateTextureFromFileInMemoryEx` creates the managed texture.
- The JAZ branch initializes its result to true. If decoding returns null,
  native consequently returns true without creating a texture; the scratch
  preserves this observed behavior.
- Non-JAZ lookup data uses `D3DXCreateTextureFromFileInMemoryEx`. Ordinary disk
  paths use `D3DXCreateTextureFromFileExA`. Both success paths copy image-info
  width and height into the texture object; both failure paths clear the
  texture and return false.
- Native does not release the disk source buffer or decoded image in this
  function, so the exact reconstruction preserves those observed leaks.

## Exact-match closure

Live Binary Ninja disassembly shows stable ownership across the full function:
`ESI` holds the path, `EBP` starts as `this` and is later reused for JAZ source
size, `EBX` holds the texture-field address, and `EDI` carries source data from
lookup discovery through disk allocation and decoding.

The previous reconstruction split lookup payload and JAZ source data into two
locals. VC6 therefore swapped the native `EBP`/`EDI` ownership and reached only
85.96%. Reconstructing the native single-owner lifetime as `source_data` raises
the result to 94.89%, keeps 235 instructions, improves the exact prefix from 5
to 41 instructions, and raises audited references from `24/0/0` to `25/0/0`.

With that ownership fixed, the ordinary branch-local `bool result = true`
produces the native extension schedule: load `grim_lookup_blob_loaded`, publish
the true result byte, then test the global. It also removes the final one-byte
layout shift and closes the function at 100%. The earlier predicate-derived
result was only compensating for the split source-data lifetime and is no
longer retained.

Exact neighboring texture routines use the same direct member ownership, and
the branch-local true result agrees with native disassembly. No volatile state,
dummy dependency, forced address, fake helper, register forcing, or layout-only
arithmetic is retained.
