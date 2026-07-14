#include <string.h>

#include "crimsonland_audio.h"

extern "C" int sfx_load_sample(char *path)
{
    int result;
    void **pcm_data;
    char *load_path;
    char buffer[128];

    if (config_blob.sound_disabled) {
        return 1;
    }

    result = 0;
    pcm_data = &sfx_entry_table[result].pcm_data;
    while (*pcm_data != 0) {
        pcm_data += 33;
        ++result;
        if (pcm_data >= &sfx_entry_table[128].pcm_data) {
            return -1;
        }
    }
    if (result == -1) {
        return -1;
    }

    load_path = path;
    if (strcmp(path, ".ogg") == 0) {
        console_printf(
            &console_log_queue,
            "Warning: sample '%s' not accepted.\n",
            path);
        load_path = "trooper_inPain_01.ogg";
    }

    if (strstr(load_path, ".ogg") != 0) {
        if (audio_resource_pack_available) {
            crt_sprintf(buffer, "%s", load_path);
        } else {
            crt_sprintf(buffer, "sfx\\%s", load_path);
        }
        if (!sfx_entry_load_ogg(&sfx_entry_table[result], buffer)) {
            console_printf(
                &console_log_queue,
                "...loading ogg sample '%s' failed\n",
                load_path);
            return -1;
        }
    } else if (!sfx_entry_load_wav(&sfx_entry_table[result], load_path)) {
        console_printf(
            &console_log_queue,
            "...loading wav sample '%s' failed\n",
            load_path);
        return -1;
    }

    if (cv_silentloads->value == 0.0f) {
        console_printf(
            &console_log_queue,
            "SFX Sample %d <- '%s' ok\n",
            result,
            load_path);
    }
    ++audio_assets_loaded_count;
    return result;
}
