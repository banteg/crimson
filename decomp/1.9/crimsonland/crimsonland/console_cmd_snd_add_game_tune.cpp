#include "crimsonland_audio.h"

extern "C" int console_cmd_argc_get(void);

extern "C" void console_cmd_snd_add_game_tune(void)
{
    char path[1024];

    if (console_cmd_argc_get() != 2) {
        console_printf(
            &console_log_queue, "snd_addGameTune <tuneName.ogg>\n");
        return;
    }

    crt_sprintf(path, "music\\%s", console_cmd_arg_get(1));
    int track_id = music_load_track(path);
    if (track_id >= 0) {
        music_queue_track(track_id);
    }
}
