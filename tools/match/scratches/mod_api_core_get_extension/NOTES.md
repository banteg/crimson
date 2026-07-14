# mod_api_core_get_extension

Native target: `crimsonland.exe` at `0x40e100` (231 bytes).

Extension matching is case-sensitive. `"GrimGFX"` returns
`grim_interface_ptr`, `"GrimSFX"` explicitly returns null, and
`"IDirect3D8"` returns pointer word 3 from Grim config slot `0x51`; unknown
names return null. The direct temporary config expression reproduces VC6's
hidden-return-pointer access and matches all 101 instructions and all 5
references exactly.
