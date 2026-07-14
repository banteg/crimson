# grim_apply_render_state

The helper at `0x10004520` is called after initial Direct3D setup and every
successful device reset, as well as from the relevant window activation paths.
It reapplies the engine's fixed render states, stage-zero modulation/filtering,
stage-one disable state, texture-coordinate selection, wrap state, geometry
buffers, and `XYZRHW | DIFFUSE | TEX1` vertex format (`0x144`).

The final state writes restore alpha blending from config records `0x12`,
`0x13`, and `0x14`. Dithering comes from config record `0x58`, revealing that
record's purpose. Boolean records are masked to their low byte exactly as in
the native code.

The natural sequence matches all 232 native instructions and all 41 references
under MSVC 6.5 `/O2 /GB`, and confirms the helper has a `void` return type.
