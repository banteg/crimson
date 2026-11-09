// crimson.exe 1.0.2, 0x410120.
#include <string.h>
#include <windows.h>

#include "grim2d_cpp.h"

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr;
extern unsigned char freeware_safe_mode;
extern int freeware_arena_width, freeware_arena_height;
extern int freeware_particle_texture, terrain_render_target, freeware_blood_texture;
extern int freeware_creature_texture, freeware_player_texture, freeware_bullet_texture;
extern int freeware_bullet_icon, aim64_texture, world_arrow_marker_texture;
extern char s_empty_string[];
extern char *freeware_main_labels[6], *freeware_option_labels[9], *freeware_town_choices[3];
extern float freeware_simulation_clock;

IGrim2D_cpp *grim_load_interface(char *);
unsigned char game_frame_update();
unsigned char sfx_system_init();
void freeware_draw_loading_progress(float);
char *strdup_malloc(char *);
void gameplay_reset_state();
void perks_init_database();
void effect_uv_tables_init();
void crt_srand(unsigned int);
void crt_free(void *);
void audio_shutdown_all();
}

extern "C" int WINAPI crimsonland_main(HINSTANCE, HINSTANCE, LPSTR, int)
{
    freeware_safe_mode = 0;
    grim_interface_ptr = grim_load_interface("..\\grim_grSystem\\Release\\grim.dll");
    if (!grim_interface_ptr) {
        grim_interface_ptr = grim_load_interface("grim.dll");
        if (!grim_interface_ptr) {
            MessageBoxA(0, "Grim.dll is corrupted or missing.", "Grim", MB_OK);
            return 0;
        }
    }

    if (!grim_interface_ptr->grim_apply_config()) {
        grim_interface_ptr->grim_release();
        return 0;
    }

    grim_interface_ptr->grim_set_config_var(1, game_frame_update);
    grim_interface_ptr->grim_set_config_var(0x42, true);
    grim_interface_ptr->grim_set_config_var(2, "crimsonland");
    grim_interface_ptr->grim_set_config_var(4, 640u);
    grim_interface_ptr->grim_set_config_var(5, 480u);
    if (freeware_safe_mode)
        grim_interface_ptr->grim_set_config_var(6, 16u);
    if (freeware_safe_mode)
        grim_interface_ptr->grim_set_config_var(3, false);
    grim_interface_ptr->grim_set_config_var(7, true);
    grim_interface_ptr->grim_set_config_var(8, true);

    if (!grim_interface_ptr->grim_init_system()) {
        MessageBoxA(0, grim_interface_ptr->grim_get_error_text(), "Crimsonland:", MB_OK);
        grim_interface_ptr->grim_release();
        return 0;
    }

    grim_interface_ptr->grim_set_config_var(0xc, true);
    grim_interface_ptr->grim_set_config_var(0xd, 5u);
    grim_interface_ptr->grim_set_config_var(0xe, 6u);
    grim_interface_ptr->grim_set_config_var(0x11, 1.0f);
    grim_interface_ptr->grim_set_config_var(0xb, "crimson.paq");
    grim_interface_ptr->grim_load_texture("crimsonland", "crimsonland.tga");
    grim_interface_ptr->grim_load_texture("bullet", "bullet.tga");
    freeware_draw_loading_progress(.1f);
    if (!sfx_system_init()) {
        MessageBoxA(0, "FMOD fails for some reason.", "Crimsonland:", MB_OK);
        grim_interface_ptr->grim_release();
        return 0;
    }

    if (!freeware_safe_mode && !grim_interface_ptr->grim_create_texture(
            "ground", freeware_arena_width, freeware_arena_height))
        freeware_safe_mode = 1;
    if (freeware_safe_mode)
        grim_interface_ptr->grim_load_texture("ground", "ground_tile.tga");
    freeware_draw_loading_progress(.25f);
    grim_interface_ptr->grim_load_texture("weapons", "weapons.tga");
    grim_interface_ptr->grim_load_texture("ugluk", "borg_t.tga");
    grim_interface_ptr->grim_load_texture("goblin", "eiliens.tga");
    grim_interface_ptr->grim_load_texture("stains", "blood.tga");
    grim_interface_ptr->grim_load_texture("aim128", "aim128.tga");
    grim_interface_ptr->grim_load_texture("aim64", "aim64.tga");
    grim_interface_ptr->grim_load_texture("aim32", "aim32.tga");
    grim_interface_ptr->grim_load_texture("arrow", "arrow.tga");
    grim_interface_ptr->grim_load_texture("reaper", "reaper.tga");
    grim_interface_ptr->grim_load_texture("perks01", "perks02.tga");
    freeware_draw_loading_progress(.45f);
    grim_interface_ptr->grim_load_texture("grass", "grass1.tga");
    grim_interface_ptr->grim_load_texture("mud", "mud1.tga");
    grim_interface_ptr->grim_load_texture("gnd_smallrocks", "gnd_smallrocks.tga");
    grim_interface_ptr->grim_load_texture("gnd_bdirt", "gnd_bdirt.tga");
    grim_interface_ptr->grim_load_texture("bullet_i", "bullet_real_16.tga");
    grim_interface_ptr->grim_load_texture("part", "part64.tga");
    grim_interface_ptr->grim_load_texture("flame", "flame.tga");
    grim_interface_ptr->grim_load_texture("glow", "glow64.tga");
    grim_interface_ptr->grim_load_texture("shockwave", "shockwave.tga");
    freeware_draw_loading_progress(.55f);
    grim_interface_ptr->grim_load_texture("ui_text", "ui_text.tga");
    grim_interface_ptr->grim_load_texture("bar", "panel.tga");
    grim_interface_ptr->grim_load_texture("b_freeze", "bonus_freeze.tga");
    grim_interface_ptr->grim_load_texture("b_bomb", "bonus_bomb.tga");
    grim_interface_ptr->grim_load_texture("b_weapon", "bonus_weapon.tga");
    grim_interface_ptr->grim_load_texture("b_fire", "bonus_fire.tga");
    freeware_particle_texture = grim_interface_ptr->grim_get_texture_handle("part");
    terrain_render_target = grim_interface_ptr->grim_get_texture_handle("ground");
    freeware_blood_texture = grim_interface_ptr->grim_get_texture_handle("stains");
    freeware_creature_texture = grim_interface_ptr->grim_get_texture_handle("goblin");
    freeware_player_texture = grim_interface_ptr->grim_get_texture_handle("ugluk");
    freeware_bullet_texture = grim_interface_ptr->grim_get_texture_handle("bullet");
    freeware_draw_loading_progress(.75f);
    freeware_bullet_icon = grim_interface_ptr->grim_get_texture_handle("bullet_i");
    aim64_texture = grim_interface_ptr->grim_get_texture_handle("aim64");
    world_arrow_marker_texture = grim_interface_ptr->grim_get_texture_handle("arrow");
    grim_interface_ptr->grim_set_config_var(0xb, s_empty_string);
    freeware_draw_loading_progress(1.f);

    memset(freeware_main_labels, 0, sizeof(freeware_main_labels));
    memset(freeware_option_labels, 0, sizeof(freeware_option_labels));
    freeware_main_labels[0] = strdup_malloc("Begin.");
    freeware_main_labels[1] = strdup_malloc("Game mode: career");
    freeware_main_labels[2] = strdup_malloc("Highscores.");
    freeware_main_labels[3] = strdup_malloc("Credits.");
    freeware_main_labels[4] = strdup_malloc("Options.");
    freeware_main_labels[5] = strdup_malloc("End.");
    freeware_option_labels[0] = strdup_malloc("Control method: static");
    freeware_option_labels[1] = strdup_malloc("Sound volume: default");
    freeware_option_labels[2] = strdup_malloc("Shadows: on");
    freeware_option_labels[3] = strdup_malloc("Background filter: smooth");
    freeware_option_labels[4] = strdup_malloc("Show FPS: off");
    freeware_option_labels[5] = strdup_malloc("Flame Glow FX: off");
    freeware_option_labels[6] = strdup_malloc("Shell marks: off");
    freeware_option_labels[7] = strdup_malloc(s_empty_string);
    freeware_option_labels[8] = strdup_malloc("Done");
    freeware_town_choices[0] = strdup_malloc("Walk around");
    freeware_town_choices[1] = strdup_malloc("Go pick a fight");
    freeware_town_choices[2] = strdup_malloc("Leave for good");
    gameplay_reset_state();
    grim_interface_ptr->grim_set_config_var(0xc, true);
    grim_interface_ptr->grim_set_config_var(0xd, 5u);
    grim_interface_ptr->grim_set_config_var(0xe, 6u);
    perks_init_database();
    effect_uv_tables_init();

    LARGE_INTEGER counter;
    counter.QuadPart = 31412;
    QueryPerformanceCounter(&counter);
    crt_srand(counter.LowPart);
    freeware_simulation_clock = 0.f;
    grim_interface_ptr->grim_apply_settings();

    for (int choice = 0; choice < 3; ++choice)
        crt_free(freeware_town_choices[choice]);
    for (int menu = 0; menu < 6; ++menu) {
        if (freeware_main_labels[menu])
            crt_free(freeware_main_labels[menu]);
    }
    for (int option = 0; option < 9; ++option) {
        if (freeware_option_labels[option])
            crt_free(freeware_option_labels[option]);
    }
    audio_shutdown_all();
    grim_interface_ptr->grim_shutdown();
    grim_interface_ptr->grim_release();
    return 0;
}
