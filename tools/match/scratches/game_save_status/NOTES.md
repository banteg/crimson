# `game_save_status`

Native target: `crimsonland.exe` at `0x00412a80` (400 bytes).

Live Binary Ninja evidence identifies registry sequence metadata, the 0x268-byte
status blob, a signed-byte checksum, an index-dependent byte transform, and the
success/failure reload paths. Keeping the successful file-write path as the
fallthrough and placing the open-failure block after its return reproduces the
native basic-block layout.

Verified exact with `crimson match scratch`: 123/123 normalized instructions
and all 36 references.
