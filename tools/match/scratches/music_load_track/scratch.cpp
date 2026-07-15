#include "crimsonland_audio.h"

static __inline int music_find_free_slot(void)
{
    int result;

    for (result = 0; result < 128; ++result) {
        if (music_entry_table[result].pcm_data == 0 &&
            music_entry_table[result].vorbis_stream == 0) {
            return result;
        }
    }
    return -1;
}

extern "C" int music_load_track(char *path)
{
    int result;

    ++audio_assets_loaded_count;
    result = music_find_free_slot();
    if (result == -1) {
        return result;
    }
    if (!music_entry_load_ogg(&music_entry_table[result], path)) {
        console_printf(
            &console_log_queue,
            "SFX Tune %d <- '%s' FAILED\n",
            result,
            path);
    } else {
        console_printf(
            &console_log_queue,
            "SFX Tune %d <- '%s' ok\n",
            result,
            path);
    }
    return result;
}
