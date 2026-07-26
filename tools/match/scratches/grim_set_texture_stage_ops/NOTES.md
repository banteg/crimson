# grim_set_texture_stage_ops

Native target: `grim.dll` at `0x10006030..0x1000655c` (1324 bytes).

The function selects one of seven fixed-function Direct3D 8 texture-stage
configurations. Each case consists only of ordered `SetTextureStageState`
calls, followed by a true return; unsupported mode values return false.

Microsoft Visual C++ 6.5 with `/O2 /GB /W3 /GR-` produces an exact
468-instruction match across all 1324 bytes, with a full 468-instruction prefix
and masked references `65/0/0`.

The reconstruction uses the SDK's named `D3DTSS`, `D3DTOP`, and `D3DTA`
constants. These names reproduce the native immediate values while preserving
the actual fixed-function render semantics recovered from live Binary Ninja
disassembly. In particular, modes 4 through 6 use `D3DTOP_DOTPRODUCT3`, and
mode 4 selects `D3DTA_TFACTOR` as its second color argument.
