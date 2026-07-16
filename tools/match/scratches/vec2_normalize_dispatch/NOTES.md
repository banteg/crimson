# `vec2_normalize_dispatch`

Native target: `crimsonland.exe` at `0x00452f2a` (6 bytes).

This is the hot-path stdcall entry for two-dimensional vector normalization.
It tail-dispatches the untouched destination/source arguments through the lazy
implementation slot at `0x00479658`. The slot initially names
`vec2_normalize_dispatch_init` and is retargeted by renderer backend selection;
runtime evidence observed `vec2_normalize_safe` after first use.

The same VC6 Processor Pack `/O1 /Oi /G6` profile used by the selected vector
implementation compiles the natural indirect return call to the exact single
`jmp [slot]` instruction.
