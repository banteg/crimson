# grim_d3d_init

`grim_d3d_init` at `0x10003e60` reconstructs the complete Direct3D8 startup
path: interface and caps discovery, the `Voodoo3` adapter workaround, window
creation, presentation-parameter setup, device and geometry-buffer creation,
texture-format selection, render-state setup, and embedded font/splash texture
loading.

The two resource loads call the internal 15-argument `__stdcall` wrapper at
`0x1000cb5c`. Its `retn 0x3c`, argument forwarding, and callsites identify it as
`D3DXCreateTextureFromFileInMemoryEx`. The target also intentionally continues
into render-state/resource setup after texture-format auto-selection fails and
tears down the device/window; the recovered source preserves that native
fallthrough instead of repairing it.

MSVC 6.5 `/O2 /GB /MD` emits all 323 native instructions and explains all 104
masked references. The final four-byte frame discrepancy came from the local
Wine D3D8 header: it wraps its structures in `pshpack4.h` only when
`__i386__` is defined, while VC6 identifies x86 with `_M_IX86`. Consequently,
`D3DADAPTER_IDENTIFIER8` was rounded from the native Win32 size `0x42c` to
`0x430`, and the function frame grew from `0x43c` to `0x440`.

The shared `grim_d3d8.h` wrapper now applies the DirectX Win32 pack(4) ABI
explicitly. That restores the native structure size and exact frame without a
function-local layout trick, and a full 196-scratch status pass confirms that
the ABI correction introduces no regressions.
