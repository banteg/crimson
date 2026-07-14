# music_release_all

When the global audio-active flag is set, releases all 128 music entries and
flushes the console log. The native guard reuses `sfx_unmuted_flag`; it does not
consult the music-disabled configuration byte here.

Exact 16/16-instruction match with all seven native references aligned.
