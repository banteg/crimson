# Native mod API audio surface

The seven SDK audio slots are native `mod_api_cpp_t` virtual methods. Sample
and tune loading both prefix filenames with `"mods\\"` in a 260-byte local
path; they then dispatch to `sfx_load_sample` and `music_load_track`
respectively. Their release methods return the underlying byte result.

All seven methods match exactly under MSVC 6.5 `/O2`, including the two
apparently surprising SDK tune slots: play calls `sfx_play_exclusive`, while
stop calls `sfx_mute_all`.
