# audio_resume_channels

Restarts active music entries after suspension, skipping indices marked in the
shared 128-byte mute table. The same sound/music enable guards as suspension
apply.

The source-level index loop explains the simultaneous music-entry pointer and
mute-table integer index in native code. Exact 26/26-instruction match with all
seven native references aligned.
