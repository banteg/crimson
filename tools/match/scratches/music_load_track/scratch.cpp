#include "crimsonland_audio.h"

extern "C" int music_load_track(char *path)
{
    int result;

    ++audio_assets_loaded_count;
    for (result = 0; result < 128; ++result) {
        if (music_entry_table[result].pcm_data == 0 &&
            music_entry_table[result].vorbis_stream == 0) {
            break;
        }
    }
    if (result == 128) {
        return -1;
    }
    if (result == -1) {
        return -1;
    }
    if (music_entry_load_ogg(&music_entry_table[result], path)) {
        console_printf(
            &console_log_queue,
            "SFX Tune %d <- '%s' ok\n",
            result,
            path);
    } else {
        console_printf(
            &console_log_queue,
            "SFX Tune %d <- '%s' FAILED\n",
            result,
            path);
    }
    return result;
}
