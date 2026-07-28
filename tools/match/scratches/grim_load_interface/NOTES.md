# grim_load_interface

Native target: `crimsonland.exe` at `0x0041dc80` (83 bytes).

The loader retains the `LoadLibraryA` result, resolves the exact
`GRIM__GetInterface` export, and copies the requested DLL path into a 256-byte
global buffer before checking whether export lookup succeeded. The next
separately constructed global starts exactly 0x100 bytes after the buffer.
A failed module
load or missing export returns null; otherwise the export's interface pointer
is returned directly.

The inline `strcpy` explains the native `repne scasb` length scan followed by
aligned `rep movsd` and tail `rep movsb` copies under MSVC 6.5.
