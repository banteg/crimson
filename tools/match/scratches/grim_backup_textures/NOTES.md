# grim_backup_textures

`grim_backup_textures` at `0x100028d0` is the pre-device-reset half of dynamic
texture preservation. Unless a backup is already pending, it visits every
owned texture, allocates a system-memory image surface with the texture's
dimensions and current format, acquires mip level zero, and copies that level
into the backup surface. The temporary mip surface is released after a
successful copy, and the pending flag is set after the full scan.

All failure paths preserve the native diagnostics and cleanup. A failed
surface-level acquisition releases the newly allocated backup. A failed copy
releases both surfaces, asserts config record `0x57`, and distinguishes
`D3DERR_DEVICELOST`, `D3DERR_INVALIDCALL`, and the generic HRESULT trace.

The recovered `bool` function matches all 219 native instructions and all 41
references under MSVC 6.5 `/O2 /GB`. The fixed `(char *, int)` declaration of
`grim_noop` is source-significant: VC6 combines cleanup for adjacent logger
calls exactly as in the native function, whereas a variadic declaration does
not.
