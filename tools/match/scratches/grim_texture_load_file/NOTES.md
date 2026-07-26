# grim_texture_load_file

Native target: `grim.dll` at `0x10004ec0..0x1000510f` (591 bytes).

This is an evidence-backed semantic-complete reconstruction, not an exact
match. Microsoft Visual C++ 6.5 with `/O2 /GB /W3 /GR- /GX /MD` produces 223
normalized instructions against 235 native instructions, with 64.19%
similarity and masked references `24/0/0`.

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
`esi`, `ebp`, `ebx`, and `edi`, spilling the lookup-hit byte into the 0x30-byte
frame. The natural VC6.5 reconstruction instead keeps that byte in `bl`,
spills `this`, and emits a 0x2c-byte frame. It also merges the two equivalent
non-JAZ success epilogues, accounting for the 12-instruction count delta.

The following diagnostic variants were rejected rather than retained:

- `msvc6.5pp` spills the byte and uses the native frame size, but hoists the
  lookup-loaded global across the extension branch and merges more tails.
- Marking the byte `volatile` reaches 79.66%, but adds two real instructions
  and has no semantic basis.
- Giving each branch a separate image-info local prevents tail merging but
  grows the frame to 0x48 because VC6 does not reuse the slots.
- Reversing one width/height assignment prevents tail merging and reaches the
  native instruction count, but emits the wrong store order.
- `/O1`, `/G5`, `/G6`, explicit `this` aliases, named HRESULT temporaries, and
  alternate `if`/`else` spellings either do not resolve the allocation or
  degrade the match.

No volatile state, dummy reference, forced address, fake helper, or
layout-only arithmetic is retained. The residual is a compiler allocation and
tail-placement problem, not unresolved behavior, so the scratch is classified
as semantic-complete with a compiler residual.
