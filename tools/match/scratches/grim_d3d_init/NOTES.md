# grim_d3d_init WIP

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

MSVC 6.5 `/O2 /GB /MD` emits the same 323 instructions in the same order and
explains all 104 masked references. It remains an honest 97.21% WIP because the
compiler reserves `0x440` bytes for the natural source while the native frame
reserves `0x43c`; the only instruction differences are that immediate in the
prologue and eight return epilogues. Era compiler variants and ordinary
optimizer/source-shape alternatives retained the four-byte discrepancy, so no
register forcing or frame-size fakematch is used.
