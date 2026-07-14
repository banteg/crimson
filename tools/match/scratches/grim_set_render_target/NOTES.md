# grim_set_render_target

`grim_set_render_target` is the vtable slot `0x30` method at `0x10006d50`.
Its native return paths only set or clear `AL`, identifying the return type as
`bool` rather than the provisional `int` declaration.

Negative handles restore the cached backbuffer, release its saved reference,
and clear both surface globals. Nonnegative handles release any previous
render-target surface, lazily retain the current backbuffer, acquire mip level
zero from `grim_texture_slots[target_index]`, and install that surface as the
device render target. The return from `GetRenderTarget` is intentionally
ignored, matching the native control flow.

The recovered method matches all 89 native instructions and all 19 references
under MSVC 6.5 `/O2 /GB`.
