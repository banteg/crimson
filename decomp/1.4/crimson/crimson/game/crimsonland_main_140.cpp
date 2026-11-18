// crimson.exe 1.4.0, 0x420710.
#include <string.h>
#include <windows.h>
#include <urlmon.h>

#include "crimsonland_console.h"
#include "freeware_config.h"
#include "freeware_level.h"
#include "grim2d_cpp.h"

void freeware_console_cmd_loadtile();

namespace frame_update140 { unsigned char game_frame_update(); }

extern "C" {
extern IGrim2D_cpp *grim_interface_ptr, *freeware_console_grim;
extern bool freeware_safe_mode, freeware_audio_disabled;
extern unsigned char freeware_music_unavailable, freeware_open_site;
extern unsigned char freeware_solstice, freeware_birthday, freeware_memorial, freeware_christmas;
extern int freeware_assembly_sequence;
extern int screen_width, screen_height, freeware_arena_width, freeware_arena_height;
extern float screen_width_f, screen_height_f, freeware_simulation_clock;
extern float freeware_snow_y[1024];
extern int freeware_particle_texture, terrain_render_target, freeware_blood_texture;
extern int freeware_creature_texture, freeware_player_texture, freeware_bullet_texture;
extern int freeware_ice_texture, freeware_bullet_icon, aim64_texture, world_arrow_marker_texture;
extern char s_empty_string[], secret_hint_magic_paint[];
extern char *freeware_main_labels[8], *freeware_option_labels[12], *freeware_online_labels[5];
extern char *freeware_update_info;

IGrim2D_cpp *grim_load_interface(char *);
bool config_load_presets();
unsigned char audio_suspend_all(), audio_resume_all(), sfx_system_init();
void freeware_console_cmd_givegun(), freeware_console_cmd_giveperk(), freeware_console_cmd_playsample();
void freeware_console_cmd_setcreaturecolor(), freeware_console_cmd_setcreaturehealth();
void freeware_console_cmd_spawncreature(), freeware_console_cmd_mergehighs();
void console_cmd_tell_time_survived(), console_cmd_set_resource_paq(), console_cmd_load_texture();
void console_cmd_open_url(), console_cmd_snd_freq_adjustment();
bool texture_get_or_load(char *name, char *path);
void freeware_draw_loading_progress(float);
void freeware_music_load_intro(), freeware_music_start(int), audio_init_sfx();
void freeware_audio_load_additional_assets(), audio_shutdown_all();
void gameplay_reset_state(), freeware_score_key_init(), perks_init_database(), effect_uv_tables_init();
bool freeware_save_config();
void freeware_brush_clear();
void crt_srand(unsigned int);
int crt_rand();
void crt_free(void *);
}

extern "C" int WINAPI crimsonland_main(HINSTANCE, HINSTANCE, LPSTR, int)
{
    console_log_queue.console_register_command("givegun", freeware_console_cmd_givegun);
    console_log_queue.console_register_command("giveperk", freeware_console_cmd_giveperk);
    console_log_queue.console_register_command("playsample", freeware_console_cmd_playsample);
    console_log_queue.console_register_command("setcreaturecolor", freeware_console_cmd_setcreaturecolor);
    console_log_queue.console_register_command("setcreaturehealth", freeware_console_cmd_setcreaturehealth);
    console_log_queue.console_register_command("spawncreature", freeware_console_cmd_spawncreature);
    console_log_queue.console_register_command("telltimesurvived", console_cmd_tell_time_survived);
    console_log_queue.console_register_command("setresourcepaq", console_cmd_set_resource_paq);
    console_log_queue.console_register_command("loadtexture", console_cmd_load_texture);
    console_log_queue.console_register_command("loadtile", freeware_console_cmd_loadtile);
    console_log_queue.console_register_command("mergehighs", freeware_console_cmd_mergehighs);
    console_log_queue.console_register_command("openurl", console_cmd_open_url);
    console_log_queue.console_register_command("sndfreqadjustment", console_cmd_snd_freq_adjustment);

    freeware_safe_mode = 0;
    grim_interface_ptr = grim_load_interface("..\\grim_grSystem_c\\Release\\grim.dll");
    console_printf(&console_log_queue, "----------------------\n");
    console_printf(&console_log_queue, "----- Grim2D API -----\n");
    console_printf(&console_log_queue, "----------------------\n");
    console_printf(&console_log_queue, "Initiating Grim\n");
    if (!grim_interface_ptr) {
        console_printf(&console_log_queue, "...DEV dll not found, trying to find REL dll\n");
        grim_interface_ptr = grim_load_interface("grim.dll");
        if (!grim_interface_ptr) {
            MessageBoxA(0, "Grim.dll is corrupted or missing.\n\n(You also might have too old\n"
                           "DirectX version installed. Try\n(re)installing DX8.1 or above)", "Grim", MB_OK);
            return 0;
        }
    }

    console_printf(&console_log_queue, "...interface created\n");
    freeware_console_grim = grim_interface_ptr;
    console_printf(&console_log_queue, "...loading config pre-sets\n");
    config_load_presets();
    console_printf(&console_log_queue, "...invoking grim config\n");
    if (!grim_interface_ptr->grim_apply_config()) {
        grim_interface_ptr->grim_release();
        return 0;
    }

    console_printf(&console_log_queue, "...setting system states\n");
    freeware_safe_mode = (bool)grim_interface_ptr->grim_get_config_var(0x54);
    freeware_audio_disabled = (bool)grim_interface_ptr->grim_get_config_var(0x53);
    config_blob.safe_mode = freeware_safe_mode;
    config_blob.audio_disabled = freeware_audio_disabled;
    config_blob.windowed = (bool)grim_interface_ptr->grim_get_config_var(6);
    if (freeware_safe_mode)
        console_printf(&console_log_queue, "...using SAFEMODE fallback backend\n");
    else
        console_printf(&console_log_queue, "...using PRIMARY backend\n");

    grim_interface_ptr->grim_set_config_var(1, frame_update140::game_frame_update);
    grim_interface_ptr->grim_set_config_var(2, audio_suspend_all);
    grim_interface_ptr->grim_set_config_var(3, audio_resume_all);
    grim_interface_ptr->grim_set_config_var(0x42, true);
    console_printf(&console_log_queue, "...setting system states\n");
    grim_interface_ptr->grim_set_config_var(5, "Crimsonland");
    screen_width = grim_interface_ptr->grim_get_config_var(7).words[0];
    screen_height = grim_interface_ptr->grim_get_config_var(8).words[0];
    if (freeware_safe_mode)
        grim_interface_ptr->grim_set_config_var(9, 16u);
    if (!config_blob.windowed && !freeware_safe_mode)
        console_printf(&console_log_queue, "...selected fullscreen mode %dx%dx%d",
                       screen_width, screen_height, config_blob.display_bpp);
    else
        console_printf(&console_log_queue, "...selected windowed mode, window size %dx%d",
                       screen_width, screen_height);

    freeware_music_unavailable = config_blob.music_disabled;
    if (freeware_safe_mode)
        grim_interface_ptr->grim_set_config_var(6, false);
    grim_interface_ptr->grim_set_config_var(0xb, true);
    console_printf(&console_log_queue, "...using keyboard\n");
    grim_interface_ptr->grim_set_config_var(0xc, true);
    console_printf(&console_log_queue, "...using mouse\n");
    grim_interface_ptr->grim_set_config_var(0xe, true);
    console_printf(&console_log_queue, "...using joystic\n");
    console_printf(&console_log_queue, "...initiating Grim system\n");
    if (!grim_interface_ptr->grim_init_system()) {
        console_printf(&console_log_queue, "Critical failure.'\n");
        MessageBoxA(0, grim_interface_ptr->grim_get_error_text(), "Crimsonland:", MB_OK);
        grim_interface_ptr->grim_release();
        return 0;
    }
    console_printf(&console_log_queue, "...refreshing the grim reaper'\n");
    grim_interface_ptr->grim_set_config_var(0x12, true);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_set_config_var(0x18, 1.0f);
    screen_width_f = (float)screen_width;
    screen_height_f = (float)screen_height;
    console_printf(&console_log_queue, "Init Grim successful.'\n");
    console_printf(&console_log_queue, "\n");
    console_printf(&console_log_queue, "----------------------\n");
    console_printf(&console_log_queue, "- Sound init ---------\n");
    console_printf(&console_log_queue, "----------------------\n");
    if (!freeware_audio_disabled) {
        if (!sfx_system_init())
            freeware_audio_disabled = true;
    } else {
        console_printf(&console_log_queue, "...no sounds selected\n");
    }

    console_printf(&console_log_queue, "\n");
    bool custom_monsters = texture_get_or_load("goblin", "override\\monsters.tga");
    grim_interface_ptr->grim_set_config_var(0x10, "crimson.paq");
    console_printf(&console_log_queue, "Set resource paq to 'crimson.paq'\n");
    texture_get_or_load("crimsonland", "crimsonland.tga");
    texture_get_or_load("bullet", "bullet.tga");
    freeware_draw_loading_progress(.1f);
    freeware_draw_loading_progress(.15f);
    freeware_music_load_intro();
    freeware_music_start(29);
    freeware_draw_loading_progress(.2f);
    audio_init_sfx();
    freeware_draw_loading_progress(.25f);
    freeware_audio_load_additional_assets();

    if (!freeware_safe_mode && !grim_interface_ptr->grim_create_texture(
            "ground", freeware_arena_width, freeware_arena_height))
        freeware_safe_mode = 1;
    if (freeware_safe_mode)
        texture_get_or_load("ground", "ground_tile.tga");
    freeware_draw_loading_progress(.3f);
    texture_get_or_load("conback", "conback.tga");
    texture_get_or_load("ugluk", "borg_t.tga");
    if (!custom_monsters)
        texture_get_or_load("goblin", "eiliens.tga");
    texture_get_or_load("stains", "blood.tga");
    texture_get_or_load("aim128", "aim128.tga");
    texture_get_or_load("aim64", "aim64.tga");
    texture_get_or_load("aim32", "aim32.tga");
    texture_get_or_load("arrow", "arrow.tga");
    texture_get_or_load("reaper", "reaper.tga");
    freeware_draw_loading_progress(.45f);
    texture_get_or_load("bullet_i", "bullet_real_16.tga");
    texture_get_or_load("part", "part64.tga");
    texture_get_or_load("flame", "flame.tga");
    texture_get_or_load("glow", "glow64.tga");
    texture_get_or_load("icemold", "icemold.tga");
    texture_get_or_load("shockwave", "shockwave.tga");
    freeware_draw_loading_progress(.55f);
    texture_get_or_load("ui_text", "ui_text.tga");
    texture_get_or_load("bar", "panel.tga");
    texture_get_or_load("b_freeze", "bonus_freeze.tga");
    texture_get_or_load("b_bomb", "bonus_bomb.tga");
    texture_get_or_load("b_weapon", "bonus_weapon.tga");
    texture_get_or_load("b_fire", "bonus_fire.tga");
    texture_get_or_load("b_timebend", "bonus_timebend.tga");
    texture_get_or_load("rocket", "rocket.tga");
    texture_get_or_load("smoke", "smoke.tga");
    texture_get_or_load("aimen", "aim_enh.tga");
    texture_get_or_load("spot", "spot.tga");
    texture_get_or_load("radius", "radius256.tga");
    texture_get_or_load("asmlogo", "assembly-logo.tga");
    texture_get_or_load("bubble", "bubble.tga");
    console_log_queue.exec_line("exec autoexec.txt");
    freeware_draw_loading_progress(.6f);
    freeware_particle_texture = grim_interface_ptr->grim_get_texture_handle("part");
    terrain_render_target = grim_interface_ptr->grim_get_texture_handle("ground");
    freeware_blood_texture = grim_interface_ptr->grim_get_texture_handle("stains");
    freeware_creature_texture = grim_interface_ptr->grim_get_texture_handle("goblin");
    freeware_player_texture = grim_interface_ptr->grim_get_texture_handle("ugluk");
    freeware_bullet_texture = grim_interface_ptr->grim_get_texture_handle("bullet");
    freeware_ice_texture = grim_interface_ptr->grim_get_texture_handle("icemold");
    freeware_draw_loading_progress(.7f);
    freeware_bullet_icon = grim_interface_ptr->grim_get_texture_handle("bullet_i");
    aim64_texture = grim_interface_ptr->grim_get_texture_handle("aim64");
    world_arrow_marker_texture = grim_interface_ptr->grim_get_texture_handle("arrow");
    console_printf(&console_log_queue, "Unloaded resource paq\n");
    grim_interface_ptr->grim_set_config_var(0x10, s_empty_string);
    freeware_draw_loading_progress(1.f);
    memset(freeware_main_labels, 0, sizeof(freeware_main_labels));
    memset(freeware_option_labels, 0, sizeof(freeware_option_labels));
    memset(freeware_online_labels, 0, sizeof(freeware_online_labels));
    freeware_online_labels[0] = strdup_malloc("Visit Crimsonland website");
    freeware_online_labels[1] = strdup_malloc("Check for updates");
    freeware_online_labels[2] = strdup_malloc("View online highscores");
    freeware_online_labels[3] = strdup_malloc(s_empty_string);
    freeware_online_labels[4] = strdup_malloc("back to main menu");
    freeware_main_labels[0] = strdup_malloc("Begin game.");
    freeware_main_labels[1] = strdup_malloc("Players: one");
    freeware_main_labels[2] = strdup_malloc("Game mode: career");
    freeware_main_labels[3] = strdup_malloc("Highscores.");
    freeware_main_labels[4] = strdup_malloc("Credits.");
    freeware_main_labels[5] = strdup_malloc("Game options.");
    freeware_main_labels[6] = strdup_malloc("Online options.");
    freeware_main_labels[7] = strdup_malloc("End.");
    freeware_option_labels[0] = strdup_malloc("Configure for: Player 1");
    freeware_option_labels[1] = strdup_malloc("Control method: kb static");
    freeware_option_labels[2] = strdup_malloc("Aiming device: mouse");
    freeware_option_labels[3] = strdup_malloc("Music: on");
    freeware_option_labels[4] = strdup_malloc("Background filter: smooth");
    freeware_option_labels[5] = strdup_malloc("Show FPS: off");
    freeware_option_labels[6] = strdup_malloc("Glow, Smoke & Shadow FX: off");
    freeware_option_labels[7] = strdup_malloc("Shell marks: off");
    freeware_option_labels[8] = strdup_malloc("Direction Arrow: on");
    freeware_option_labels[9] = strdup_malloc("Redefine controls");
    freeware_option_labels[10] = strdup_malloc("Calibrate joystick");
    freeware_option_labels[11] = strdup_malloc("Done");

    freeware_current_map = new freeware_level_map;
    freeware_current_map->clear();
    gameplay_reset_state();
    freeware_score_key_init();
    freeware_update_info = strdup_malloc(s_empty_string);
    grim_interface_ptr->grim_set_config_var(0x12, true);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    perks_init_database();
    effect_uv_tables_init();
    console_printf(&console_log_queue, "Entering Crimsonland..\n");
    SYSTEMTIME date;
    GetLocalTime(&date);
    console_printf(&console_log_queue, "Time check: %d %d %d\n", date.wDay, date.wMonth, date.wYear);
    if (date.wYear == 2012 && date.wMonth == 12)
        freeware_solstice = 1;
    if (date.wMonth == 8 && date.wDay >= 1 && date.wDay <= 4)
        freeware_assembly_sequence = 8;
    if (date.wMonth == 9 && date.wDay == 12)
        freeware_birthday = 1;
    if (date.wMonth == 12 && date.wDay >= 24 && date.wDay <= 25)
        freeware_christmas = 1;
    if (date.wMonth == 9 && date.wDay == 11)
        freeware_memorial = 1;

    LARGE_INTEGER counter;
    counter.QuadPart = date.wMilliseconds;
    QueryPerformanceCounter(&counter);
    crt_srand(counter.LowPart);
    for (int flake = 0; flake < 1024; ++flake)
        freeware_snow_y[flake] = (float)(crt_rand() % 1024);
    freeware_simulation_clock = 0.0f;
    if (secret_hint_magic_paint)
        freeware_simulation_clock = 0.0f;
    grim_interface_ptr->grim_apply_settings();

    freeware_save_config();
    freeware_brush_clear();
    delete freeware_current_map;
    console_printf(&console_log_queue, "Leaving Crimsonland..\n");
    if (freeware_update_info)
        crt_free(freeware_update_info);
    for (int online = 0; online < 5; ++online) {
        if (freeware_online_labels[online])
            crt_free(freeware_online_labels[online]);
    }
    for (int main = 0; main < 8; ++main) {
        if (freeware_main_labels[main])
            crt_free(freeware_main_labels[main]);
    }
    for (int option = 0; option < 12; ++option) {
        if (freeware_option_labels[option])
            crt_free(freeware_option_labels[option]);
    }

    console_log_queue.flush_log("console.log");
    audio_shutdown_all();
    console_log_queue.flush_log("console.log");
    console_printf(&console_log_queue, "Shutdown Grim..\n");
    console_log_queue.flush_log("console.log");
    grim_interface_ptr->grim_shutdown();
    console_log_queue.flush_log("console.log");
    grim_interface_ptr->grim_release();
    console_printf(&console_log_queue, "Waving the grim reaper goodbye..\n");
    console_log_queue.flush_log("console.log");

    if (freeware_open_site) {
        if (date.wYear <= 2002 && date.wMonth < 10) {
            if (HlinkNavigateString(0, L"http://crimsonland.10tons.org/") < 0)
                MessageBoxA(0, "Failed to open browser at http://crimsonland.10tons.org/", "Crimsonland", MB_ICONWARNING);
        } else {
            if (HlinkNavigateString(0, L"http://www.crimsonland.com/") < 0)
                MessageBoxA(0, "Failed to open browser at http://www.crimsonland.com/", "Crimsonland", MB_ICONWARNING);
        }
    }
    return 0;
}
