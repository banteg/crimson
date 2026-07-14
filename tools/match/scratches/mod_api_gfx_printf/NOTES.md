# mod_api_gfx_printf

Native target: `crimsonland.exe` at `0x40e240` (53 bytes).

The variadic virtual method formats into its dedicated shared buffer at
`0x4d9d00`, then draws that text with the Grim small-font method at the supplied
coordinates. Its caller-cleaned member ABI matches all 16 instructions and all
4 references exactly.
