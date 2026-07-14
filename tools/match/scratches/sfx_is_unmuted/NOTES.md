# sfx_is_unmuted

An SFX id is available only while the global audio-active flag is set and its
per-id mute byte is clear. The native helper performs no id bounds check.

Exact 11/11-instruction match with both native references aligned.
