# mod_api_gfx_draw_quads

Native target: `crimsonland.exe` at `0x40e4c0` (98 bytes).

Outside an explicit mod batch, the wrapper opens and closes a Grim batch around
the submission. It constructs a zero two-float offset after the optional open,
then passes the mod vertex array and quad count to
`grim_submit_vertices_offset`. That initialization point reproduces all 26
native instructions and all 5 references exactly.
