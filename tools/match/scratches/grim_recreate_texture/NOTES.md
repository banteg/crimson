# grim_recreate_texture

The vtable method recreates a managed one-level texture with the entry's saved
dimensions and the preferred device format. It copies the old texture through
the linked D3DX8 resampler, releases the replacement on copy failure, and only
releases and swaps the live texture after a successful copy. The six-argument
copy helper is an internal D3DX routine, not a public `D3DXLoadTexture*` API;
its body validates copy flags and filter modes and consumes the final argument
as an x87 scale, matching the call's literal `1.0f`.
