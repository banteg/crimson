# grim_save_texture

Live disassembly proves two explicit stack arguments (`handle`, `path`) and a
`retn 8`. For a populated texture slot, the function calls the statically
linked `D3DXSaveTextureToFileA(path, 2, texture, NULL)` helper and returns the
HRESULT success bit. D3DX image format `2` is TGA. This replaces the stale
one-argument `grim_validate_texture` interpretation.
