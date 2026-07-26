# grim_select_texture_format

`grim_select_texture_format` at `0x10004830` probes texture formats in this
native order and stores the first supported choice:

1. `D3DFMT_A8R8G8B8`
2. `D3DFMT_DXT3`
3. `D3DFMT_A4R4G4B4`
4. `D3DFMT_A1R5G5B5`
5. `D3DFMT_R8G8B8`
6. `D3DFMT_X8R8G8B8`
7. `D3DFMT_R8G8B8` again
8. `D3DFMT_R5G6B5`

The repeated `R8G8B8` probe is present in the binary as two independent calls
and assignments. It is retained as plausible original source behavior rather
than silently corrected to another format. If every probe fails, the function
stores `"D3D: No supported texture formats found."` and returns `false`.

The explicit early-return chain matches all 67 native instructions and all 17
references under MSVC 6.5 `/O2 /GB`.
