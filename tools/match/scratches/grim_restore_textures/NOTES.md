# grim_restore_textures

`grim_restore_textures` at `0x10002b40` is the post-device-reset half of the
dynamic-texture preservation path. It refuses to run in DC mode or without a
pending backup, then visits owned texture slots with a backup image surface.
For each slot it acquires mip level zero, copies the backup surface into it,
and releases both temporary and backup surfaces.

The `GrimTexture` member at offset `0x14` is therefore an
`IDirect3DSurface8 *`, agreeing with the `CreateImageSurface` producer in
`grim_backup_textures`. A failed `CopyRects` releases both surfaces, sets
config record `0x57` through the byte-writing boolean constructor, clears the
pending flag, and reports failure. The normal path clears the pending flag
after the full scan.

The recovered `bool` function matches all 161 native instructions and all 26
references under MSVC 6.5 `/O2 /GB`. Direct `grim_texture_slots[i]` expressions
are source-significant: VC6 reduces them to the native pointer induction form.
