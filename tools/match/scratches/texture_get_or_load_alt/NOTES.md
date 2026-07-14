# texture_get_or_load_alt

Native target: `crimsonland.exe` at `0x0042a700` (126 bytes).

This adjacent legacy loader has the same cache-miss policy but intentionally
ignores its `path` argument: it passes `name` as both cache key and path and
uses `name` in success and failure messages. Preserving that native asymmetry
matches all 40 instructions, full prefix, with all eleven references aligned.
