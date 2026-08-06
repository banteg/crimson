# Grim surface guards

The D3DX texture-copy path uses two small stack-owned guards. The four-field
copy guard tracks a flags word, destination surface, source surface, and
Direct3D device. Its release method unlocks the source surface when present,
otherwise the destination surface; conditionally copies the locked rectangle
back when both surfaces and the device exist and flag bit zero is clear; then
releases the owned source surface and device and clears all borrowed state.

The one-field lock guard only unlocks its surface, clears the pointer, and
returns zero. The typed vtable declarations preserve the observed Direct3D 8
COM ABI: `Release` at byte offset `0x08`, surface `UnlockRect` at `0x28`, and
device `CopyRects` at `0x70`, all using `__stdcall`.

VC6 SP6 with `/O1 /G6 /W3 /GR- /MD` reproduces both initializers, both release
methods, and both release forwarding thunks exactly. Together the six helpers
cover 77 instructions and 159 bytes in the explicit `all` scope, with both
thunk relocations resolved to their release methods.
