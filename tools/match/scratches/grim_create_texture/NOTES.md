# grim_create_texture

The vtable method allocates the first free handle, creates a one-level
render-target texture in the configured D3D format, constructs a 24-byte
`GrimTexture`, marks the D3D texture as owned, stores its dimensions, and
extends the high-water handle when necessary. The native SEH frame is emitted
naturally by `new GrimTexture(name)`. Assigning through the global slot, rather
than retaining a local pointer, reproduces the original repeated slot loads and
all 81 native instructions.
