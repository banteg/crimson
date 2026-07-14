# console_cmd_snd_add_game_tune

Native target: `crimsonland.exe` at `0x0042c360` (100 bytes).

The console command requires exactly one tune argument, reports its native
usage string otherwise, formats `music\\<argument>` into a 1024-byte stack
buffer, and loads it through the music registry. A nonnegative track ID is
immediately appended to the playback queue; failed loads are silently ignored.
