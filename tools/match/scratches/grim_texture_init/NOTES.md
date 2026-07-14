# grim_texture_init

The native body is the `GrimTexture(char *)` constructor. It allocates and
copies the NUL-terminated name, clears the D3D texture and backup pointers, and
clears the ownership flag. Width and height are deliberately left untouched
for the caller to fill.
