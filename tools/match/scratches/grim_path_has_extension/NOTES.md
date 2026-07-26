# `grim_path_has_extension`

Exact 99-byte, 50-instruction match with MSVC 6.5 `/O2 /GB`.

The native helper computes `strlen(string) - 3` for both inputs and compares
the three trailing bytes. Its only native caller passes the texture path and
the literal `"jaz"`, selecting the custom JAZ decode path. The post-incremented
first comparison and explicit `bool` result preserve the native register and
epilogue shape without changing those semantics.
