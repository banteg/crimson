# mods_any_available

Native target: `crimsonland.exe` at `0x0040e940` (87 bytes).

The helper enumerates `mods\\*.dll`, counts successful directory entries,
closes the search handle even when opening failed, and returns whether the
count is non-zero. The apparently redundant `finddata.name != 0` check is
present in the native instructions and is valid ordinary source against the
CRT's fixed name array.

Natural VC6 code matches all 33 instructions and references `4/0/0`.
