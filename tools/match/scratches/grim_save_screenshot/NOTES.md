# grim_save_screenshot

The vtable slot `0x0c` function at `0x10005cb0` was previously labeled
`grim_check_device`, but its body and ABI establish a screenshot operation:

- it takes one stack argument and returns a byte-sized C++ `bool`;
- it creates an `A8R8G8B8` image surface at the current presentation size;
- it calls `IDirect3DDevice8::GetFrontBuffer` into that surface;
- it passes the filename, BMP format `0`, and surface to the five-argument
  `D3DXSaveSurfaceToFileA` helper;
- it releases the surface on both failure paths and on success.

The recovered structured C++ matches all 56 native instructions and all five
references under MSVC 6.5 `/O2 /GB`. `grim_save_screenshot` is a semantic
recovery, not an assertion of the original source identifier; the old name is
retained as a map alias for provenance.
