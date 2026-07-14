# mod_api_debug_printf

Native target: `crimsonland.exe` at `0x40e000` (50 bytes).

The free variadic helper formats into a 4092-byte stack buffer and forwards the
result to `OutputDebugStringA`. It does not occupy the mod API vtable. Natural
C++ matches all 14 instructions and both references exactly.
