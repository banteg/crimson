# `grim_set_config_var`

Native target: `grim.dll` at `0x10006580..0x10006b7e` (1534 bytes).

The function is a sparse router over configuration IDs `5..85`. Its native
lookup table dispatches specialized device, input, callback, string, gamma,
window, and render routes; ordinary IDs copy a complete 16-byte
`grim_config_value_t` record. Case 26 publishes word zero after the texture
stage helper succeeds and then joins the ordinary word-one-through-three tail.

The native physical case order matches the recovered switch order exactly:
`26, 27, 28, 41, 42, 43, 7, 45, 6, 5, 16, 18, 19, 20, 52, 54`, the shared
byte cases, `13, 21, 82, 85`, then the ordinary copy tail.

## Exact closure

Two source-ownership details reproduce the native shared tails. A
function-scope configuration pointer is assigned separately by case 26 and the
ordinary route, so VC6 consumes the ID register as the destination pointer
before both paths join. In case 16, native disassembly loads the old resource
path through the dynamic ID but publishes the empty-string duplicate directly
to the known case-16 slot; spelling only that store as
`grim_config_values[16]` preserves the same asymmetric ownership.

The DLL imports `_strdup`, and compiling with the corresponding VC6 `/MD` ABI
then caches that import in the native register and closes the remaining router
offsets. The result is exact: **443/443** normalized instructions, prefix
**443**, and references **`74/0/0`**.

The source retains ordinary C++ control flow and recovered data ownership. It
uses no inline assembly, volatile shaping, fake references, forced addresses,
register forcing, or dummy operations.
