#include "crimsonland_gameplay.h"

extern "C" unsigned char time_scale_active;
extern "C" float camera_shake_offset_x;
extern "C" float camera_shake_offset_y;
extern "C" float camera_offset_x;
extern "C" float camera_offset_y;

extern "C" void camera_update(void)
{
    if (camera_shake_timer > 0.0f) {
        camera_shake_timer -= frame_dt * 3.0f;
        if (camera_shake_timer < 0.0f) {
            --camera_shake_pulses;
            if (camera_shake_pulses > 0) {
                camera_shake_timer = 0.1f;
                if (time_scale_active) {
                    camera_shake_timer = 0.06f;
                }

                int magnitude =
                    crt_rand() % (camera_shake_pulses * 60 / 20)
                    + crt_rand() % 10;
                if (crt_rand() & 1) {
                    camera_shake_offset_x = (float)magnitude;
                } else {
                    camera_shake_offset_x = (float)-magnitude;
                }

                magnitude =
                    crt_rand() % (camera_shake_pulses * 60 / 20)
                    + crt_rand() % 10;
                if (crt_rand() & 1) {
                    camera_shake_offset_y = (float)magnitude;
                } else {
                    camera_shake_offset_y = (float)-magnitude;
                }
            } else {
                camera_shake_timer = 0.0f;
            }
        }
    } else {
        camera_shake_offset_x = 0.0f;
        camera_shake_offset_y = 0.0f;
    }

    int screen_height = config_blob.screen_height;
    int screen_width = config_blob.screen_width;
    float next_camera_y;
    if (config_blob.player_count == 1) {
        camera_offset_x =
            (float)(screen_width / 2)
            - player_state_table[render_overlay_player_index].position.x;
        next_camera_y =
            (float)(screen_height / 2)
            - player_state_table[render_overlay_player_index].position.y;
        goto apply_shake;
    }

    if (player_state_table[0].health <= 0.0f) {
        if (player_state_table[1].health > 0.0f) {
            camera_offset_x =
                (float)(screen_width / 2) - player_state_table[1].position.x;
            next_camera_y =
                (float)(screen_height / 2) - player_state_table[1].position.y;
            goto apply_shake;
        }
    } else if (player_state_table[1].health > 0.0f) {
        goto focus_both_players;
    }

    if (player_state_table[0].health > 0.0f) {
        camera_offset_x =
            (float)(screen_width / 2) - player_state_table[0].position.x;
        next_camera_y =
            (float)(screen_height / 2) - player_state_table[0].position.y;
        goto apply_shake;
    }

    if (player_state_table[1].health <= 0.0f) {
        goto preserve_camera_y;
    }

focus_both_players:
    if (player_state_table[0].health > 0.0f) {
        camera_offset_x =
            (float)(screen_width / 2)
            - (player_state_table[0].position.x
               - (player_state_table[0].position.x - player_state_table[1].position.x)
                   * 0.5f);
        next_camera_y =
            (float)(screen_height / 2)
            - (player_state_table[0].position.y
               - (player_state_table[0].position.y - player_state_table[1].position.y)
                   * 0.5f);
        goto apply_shake;
    }

preserve_camera_y:
    next_camera_y = camera_offset_y;

apply_shake:
    camera_offset_y = (float)next_camera_y;
    camera_offset_x += camera_shake_offset_x;
    camera_offset_y += camera_shake_offset_y;

    if (camera_offset_x > -1.0f) {
        camera_offset_x = -1.0f;
    }
    if (camera_offset_y > -1.0f) {
        camera_offset_y = -1.0f;
    }

    float min_x = (float)(screen_width - terrain_texture_width);
    if (camera_offset_x < min_x) {
        camera_offset_x = min_x;
    }

    float min_y = (float)(screen_height - terrain_texture_height);
    if (camera_offset_y < min_y) {
        camera_offset_y = min_y;
    }
}
