# mod_api_gfx_load_texture

Native target: `crimsonland.exe` at `0x40e280` (81 bytes).

Two 260-byte locals construct `"mods\\%s"` as the source path and `"CLM_%s"`
as the texture-cache name. The wrapper calls `texture_get_or_load(name, path)`
and returns its handle. Natural source matches all 23 instructions and all 5
references exactly.
