#include "crimsonland_audio.h"

extern "C" int sfx_play_panned(
    int sfx_id,
    const vec2f_t *pos,
    float volume)
{
    int pan;
    int voice;

    if (sfx_entry_table[sfx_id].pcm_data == 0) {
        return -1;
    }
    if (config_blob.sound_disabled) {
        return -1;
    }
    if (sfx_cooldown_table[sfx_id] > 0.0f) {
        return -1;
    }

    if (bonus_reflex_boost_timer > 0.0f) {
        if (bonus_reflex_boost_timer > 1.0f) {
            sfx_rate_scale = 22050;
        } else if (bonus_reflex_boost_timer < 1.0f) {
            sfx_rate_scale =
                (DWORD)((1.0f - bonus_reflex_boost_timer + 1.0f) *
                    22050.0f);
        }
    } else {
        sfx_rate_scale = 44100;
    }

    if (demo_mode_active) {
        volume *= 0.7f;
    }

    if (sfx_id == sfx_flamer_fire_01 || sfx_id == sfx_flamer_fire_02) {
        sfx_cooldown_table[sfx_id] = 0.44f;
    } else {
        sfx_cooldown_table[sfx_id] = 0.05f;
    }

    pan = (int)(((camera_offset_x + pos->x) / (float)config_blob.screen_width -
                    0.5f) *
        1700.0f);
    if (pan < -10000) {
        pan = -10000;
    }
    if (pan > 10000) {
        pan = 10000;
    }

    voice = sfx_entry_start_playback(&sfx_entry_table[sfx_id]);
    sfx_entry_table[sfx_id].buffers[voice]->SetPan(pan);
    sfx_entry_set_volume(
        &sfx_entry_table[sfx_id],
        config_blob.sfx_volume * volume);
    return sfx_id;
}
