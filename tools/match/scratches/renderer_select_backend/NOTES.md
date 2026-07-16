# `renderer_select_backend`

Native target: `crimsonland.exe` at `0x004566d3` (221 bytes).

The selector owns the 57-entry vector/matrix dispatch table. A zero argument
copies the default table and marks the backend unknown (`0xffff`). The next
nonzero call copies defaults again, applies portable patches, reads the
`DisableD3DXPSGP` DWORD, and—unless that value is one—prefers 3DNow!, SSE2,
then SSE. Selected backend kinds are respectively 1, 2, and 3; zero denotes
the portable baseline.

All table sizes, feature IDs, branch priority, the registry gate, stdcall
entry convention, and patch calls are taken from live Binary Ninja evidence.
The active table is `0x004795a0`, defaults are `0x00479688`, and the selected
kind is stored at `0x00479770`; these globals and the six helper functions now
have canonical evidence-backed map names.

MSVC 7.0 with `/O1 /Oi /G6 /Oy-` reproduces the complete native body exactly:
72/72 normalized instructions and 20/0/0 audited references. Preserving the
frame pointer is required because the registry read takes the address of the
argument. Spelling reset first and initialization as the `else if` recovers
native's shrink-wrapped EBX save and both 57-entry `rep movsd` copies without
any register forcing or fake dependency.
