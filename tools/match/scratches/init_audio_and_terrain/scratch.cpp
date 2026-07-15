#include "crimsonland_audio.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern unsigned char sfx_init_disabled;
extern float config_texture_scale;
extern int terrain_texture_width;
extern int terrain_texture_height;
extern unsigned char terrain_texture_failed;
}

extern "C" void init_audio_and_terrain(void)
{
    console_printf(&console_log_queue, "Init Grim successful.\n");
    console_printf(&console_log_queue, "\n");
    console_printf(&console_log_queue, "----------------------\n");
    console_printf(&console_log_queue, "- Sound init ---------\n");
    console_printf(&console_log_queue, "----------------------\n");

    if (!sfx_init_disabled) {
        if (!sfx_system_init()) {
            sfx_init_disabled = 1;
        }
    } else {
        console_printf(&console_log_queue, "...no sounds selected\n");
    }
    console_printf(&console_log_queue, "\n");

    terrain_texture_width = 1024;
    terrain_texture_height = 1024;
    if (config_texture_scale < 0.5f) {
        config_texture_scale = 0.5f;
    } else if (config_texture_scale > 4.0f) {
        config_texture_scale = 4.0f;
    }

    if (!terrain_texture_failed) {
        int size = (int)(1024.0f / config_texture_scale);
        if (!grim_interface_ptr->grim_create_texture(
                "ground", size, size)) {
            float previous_scale = config_texture_scale;
            config_texture_scale += config_texture_scale;
            if (!grim_interface_ptr->grim_create_texture(
                    "ground",
                    (int)((float)terrain_texture_width
                          / config_texture_scale),
                    (int)((float)terrain_texture_height
                          / config_texture_scale))) {
                config_texture_scale = previous_scale;
                terrain_texture_failed = 1;
                console_printf(
                    &console_log_queue,
                    "Failed to create terrain texture.\n");
                console_printf(
                    &console_log_queue,
                    "--> entering safemode.\n");
            } else {
                console_printf(
                    &console_log_queue,
                    "Created terrain texture.\n");
            }
        }
    }

    if (terrain_texture_failed) {
        console_printf(
            &console_log_queue,
            "Running in safemode, using static terrain textures.\n");
    }
    console_log_queue.flush_log("console.log");
}
