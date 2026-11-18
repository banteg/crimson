// crimson.exe 1.3.0, 0x419d60.
#include <string.h>
#include <windows.h>
#include <unknwn.h>

#include "../level/freeware_editor_brush.h"

namespace frame_update140 { unsigned char game_frame_update(); }

extern "C" {
extern int screen_width, screen_height, freeware_arena_width, freeware_arena_height;
extern unsigned char freeware_audio_disabled, freeware_safe_mode, freeware_birthday;
extern int freeware_particle_texture, terrain_render_target, freeware_blood_texture;
extern int freeware_creature_texture, freeware_player_texture, freeware_bullet_texture;
extern int freeware_ice_texture, freeware_bullet_icon, aim64_texture, world_arrow_marker_texture;
extern char s_empty_string[];
extern char *freeware_main_labels[7], *freeware_option_labels[11];
extern int freeware_assembly_sequence;
extern float freeware_simulation_clock;

IUnknown *WINAPI Direct3DCreate8(unsigned int sdk_version);
IGrim2D_cpp *grim_load_interface(char *);
bool config_load_presets();
unsigned char audio_suspend_all(), audio_resume_all(), sfx_system_init();
void freeware_draw_loading_progress(float);
void freeware_music_load_intro(), freeware_game_track_start(int);
void audio_init_sfx(), freeware_audio_load_additional_assets(), audio_shutdown_all();
char *strdup_malloc(char *);
void gameplay_reset_state(), freeware_score_key_init(), perks_init_database(), effect_uv_tables_init();
bool freeware_save_config();
void freeware_brush_clear();
void crt_srand(unsigned int);
void crt_free(void *);
}

extern "C" int WINAPI crimsonland_main(HINSTANCE, HINSTANCE, LPSTR command_line, int)
{
    IUnknown *direct3d = Direct3DCreate8(220);
    if (!direct3d) {
        MessageBoxA(0, "DirectX8.1 not detected.\n\nCrimsonland needs Microsoft DirectX 8.1 installed\n"
                       "on the system. It is available for download at\nhttp://www.microsoft.com/directx",
                    "Crimsonland", MB_OK);
        return 0;
    }
    direct3d->Release();
    freeware_safe_mode = 0;
    if (strcmp(command_line, "-nosound") == 0)
        freeware_audio_disabled = 1;
    if (strcmp(command_line, "-nosounds") == 0)
        freeware_audio_disabled = 1;
    if (strcmp(command_line, "nosound") == 0)
        freeware_audio_disabled = 1;
    if (strcmp(command_line, "nosounds") == 0)
        freeware_audio_disabled = 1;
    if (strcmp(command_line, "no sound") == 0)
        freeware_audio_disabled = 1;
    if (strcmp(command_line, "no sounds") == 0)
        freeware_audio_disabled = 1;
    if (strcmp(command_line, "-safemode") == 0)
        freeware_safe_mode = 1;
    if (strcmp(command_line, "safemode") == 0)
        freeware_safe_mode = 1;
    if (strcmp(command_line, "nosound safemode") == 0 ||
        strcmp(command_line, "-nosound -safemode") == 0 ||
        strcmp(command_line, "safemode nosound") == 0 ||
        strcmp(command_line, "-nosounds -safemode") == 0) {
        freeware_safe_mode = 1;
        freeware_audio_disabled = 1;
    }
    grim_interface_ptr = grim_load_interface("..\\grim_grSystem\\Release\\grim.dll");
    if (!grim_interface_ptr) {
        grim_interface_ptr = grim_load_interface("grim.dll");
        if (!grim_interface_ptr) {
            MessageBoxA(0, "Grim.dll is corrupted or missing.\n\n(You also might have too old\n"
                           "DirectX version installed. Try\n(re)installing DX8.1 or above)", "Grim", MB_OK);
            return 0;
        }
    }
    config_load_presets();
    if (!grim_interface_ptr->grim_apply_config()) {
        grim_interface_ptr->grim_release();
        return 0;
    }

    grim_interface_ptr->grim_set_config_var(1, frame_update140::game_frame_update);
    grim_interface_ptr->grim_set_config_var(2, audio_suspend_all);
    grim_interface_ptr->grim_set_config_var(3, audio_resume_all);
    grim_interface_ptr->grim_set_config_var(0x42, true);
    grim_interface_ptr->grim_set_config_var(5, "Crimsonland");
    screen_width = grim_interface_ptr->grim_get_config_var(7).words[0];
    screen_height = grim_interface_ptr->grim_get_config_var(8).words[0];
    if (freeware_safe_mode)
        grim_interface_ptr->grim_set_config_var(9, 16u);
    if (freeware_safe_mode)
        grim_interface_ptr->grim_set_config_var(6, false);
    grim_interface_ptr->grim_set_config_var(0xb, true);
    grim_interface_ptr->grim_set_config_var(0xc, true);
    grim_interface_ptr->grim_set_config_var(0xe, true);
    if (!grim_interface_ptr->grim_init_system()) {
        MessageBoxA(0, grim_interface_ptr->grim_get_error_text(), "Crimsonland:", MB_OK);
        grim_interface_ptr->grim_release();
        return 0;
    }

    grim_interface_ptr->grim_set_config_var(0x12, true);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_set_config_var(0x18, 1.f);

    bool custom_monsters = grim_interface_ptr->grim_load_texture("goblin", "override\\monsters.tga");
    grim_interface_ptr->grim_set_config_var(0x10, "crimson.paq");
    grim_interface_ptr->grim_load_texture("crimsonland", "crimsonland.tga");
    grim_interface_ptr->grim_load_texture("bullet", "bullet.tga");
    freeware_draw_loading_progress(.1f);
    if (!freeware_audio_disabled && !sfx_system_init())
        freeware_audio_disabled = 1;
    freeware_draw_loading_progress(.15f);
    freeware_music_load_intro();
    freeware_game_track_start(29);
    freeware_draw_loading_progress(.2f);
    audio_init_sfx();
    freeware_draw_loading_progress(.25f);
    freeware_audio_load_additional_assets();

    if (!freeware_safe_mode && !grim_interface_ptr->grim_create_texture(
            "ground", freeware_arena_width, freeware_arena_height))
        freeware_safe_mode = 1;
    if (freeware_safe_mode)
        grim_interface_ptr->grim_load_texture("ground", "ground_tile.tga");
    freeware_draw_loading_progress(.3f);
    grim_interface_ptr->grim_load_texture("ugluk", "borg_t.tga");
    if (!custom_monsters)
        grim_interface_ptr->grim_load_texture("goblin", "eiliens.tga");
    grim_interface_ptr->grim_load_texture("stains", "blood.tga");
    grim_interface_ptr->grim_load_texture("aim128", "aim128.tga");
    grim_interface_ptr->grim_load_texture("aim64", "aim64.tga");
    grim_interface_ptr->grim_load_texture("aim32", "aim32.tga");
    grim_interface_ptr->grim_load_texture("arrow", "arrow.tga");
    grim_interface_ptr->grim_load_texture("reaper", "reaper.tga");
    freeware_draw_loading_progress(.45f);
    grim_interface_ptr->grim_load_texture("bullet_i", "bullet_real_16.tga");
    grim_interface_ptr->grim_load_texture("part", "part64.tga");
    grim_interface_ptr->grim_load_texture("flame", "flame.tga");
    grim_interface_ptr->grim_load_texture("glow", "glow64.tga");
    grim_interface_ptr->grim_load_texture("icemold", "icemold.tga");
    grim_interface_ptr->grim_load_texture("shockwave", "shockwave.tga");
    freeware_draw_loading_progress(.55f);
    grim_interface_ptr->grim_load_texture("ui_text", "ui_text.tga");
    grim_interface_ptr->grim_load_texture("bar", "panel.tga");
    grim_interface_ptr->grim_load_texture("b_freeze", "bonus_freeze.tga");
    grim_interface_ptr->grim_load_texture("b_bomb", "bonus_bomb.tga");
    grim_interface_ptr->grim_load_texture("b_weapon", "bonus_weapon.tga");
    grim_interface_ptr->grim_load_texture("b_fire", "bonus_fire.tga");
    grim_interface_ptr->grim_load_texture("b_timebend", "bonus_timebend.tga");
    grim_interface_ptr->grim_load_texture("rocket", "rocket.tga");
    grim_interface_ptr->grim_load_texture("smoke", "smoke.tga");
    grim_interface_ptr->grim_load_texture("aimen", "aim_enh.tga");
    grim_interface_ptr->grim_load_texture("spot", "spot.tga");
    grim_interface_ptr->grim_load_texture("radius", "radius256.tga");
    grim_interface_ptr->grim_load_texture("asmlogo", "assembly-logo.tga");
    grim_interface_ptr->grim_set_config_var(0x10, "tiles.paq");

    grim_interface_ptr->grim_load_texture("grass", "grass1.tga");
    freeware_brushes.push_back(new freeware_editor_brush("grass", 128, 128));
    grim_interface_ptr->grim_load_texture("mud", "mud1.tga");
    freeware_brushes.push_back(new freeware_editor_brush("mud", 128, 128));
    grim_interface_ptr->grim_load_texture("gnd_smallrocks", "gnd_smallrocks.tga");
    freeware_brushes.push_back(new freeware_editor_brush("gnd_smallrocks", 128, 128));
    grim_interface_ptr->grim_load_texture("gnd_bdirt", "gnd_bdirt.tga");
    freeware_brushes.push_back(new freeware_editor_brush("gnd_bdirt", 128, 128));
    grim_interface_ptr->grim_load_texture("gnd_asphalt", "gnd_asphalt.tga");
    freeware_brushes.push_back(new freeware_editor_brush("gnd_asphalt", 128, 128));
    grim_interface_ptr->grim_load_texture("tl_floor", "floor.tga");
    freeware_brushes.push_back(new freeware_editor_brush("tl_floor", 128, 256));
    grim_interface_ptr->grim_load_texture("tl_mfloor", "tl_metalfloor.tga");
    freeware_brushes.push_back(new freeware_editor_brush("tl_mfloor", 128, 128));
    grim_interface_ptr->grim_load_texture("tl_mfloor64", "tl_metalfloor64.tga");
    freeware_brushes.push_back(new freeware_editor_brush("tl_mfloor64", 64, 64));
    grim_interface_ptr->grim_load_texture("tl_bwfloor", "tl_blackwhite.tga");
    freeware_brushes.push_back(new freeware_editor_brush("tl_bwfloor", 32, 32));
    grim_interface_ptr->grim_load_texture("tl_wall_h", "tl_wall_h.tga");
    freeware_brushes.push_back(new freeware_editor_brush("tl_wall_h", 32, 32));
    grim_interface_ptr->grim_load_texture("tl_wall_v", "tl_wall_v.tga");
    freeware_brushes.push_back(new freeware_editor_brush("tl_wall_v", 32, 32));
    grim_interface_ptr->grim_load_texture("tl_wall_tl", "tl_wall_tl.jpg");
    freeware_brushes.push_back(new freeware_editor_brush("tl_wall_tl", 32, 32));
    grim_interface_ptr->grim_load_texture("tl_wall_tr", "tl_wall_tr.jpg");
    freeware_brushes.push_back(new freeware_editor_brush("tl_wall_tr", 32, 32));
    grim_interface_ptr->grim_load_texture("tl_wall_br", "tl_wall_br.jpg");
    freeware_brushes.push_back(new freeware_editor_brush("tl_wall_br", 32, 32));
    grim_interface_ptr->grim_load_texture("tl_wall_bl", "tl_wall_bl.jpg");
    freeware_brushes.push_back(new freeware_editor_brush("tl_wall_bl", 32, 32));
    grim_interface_ptr->grim_load_texture("tl_wall_block_h", "tl_wall_block_h.tga");
    freeware_brushes.push_back(new freeware_editor_brush("tl_wall_block_h", 32, 32));
    grim_interface_ptr->grim_load_texture("tl_wall_block_v", "tl_wall_block_v.tga");
    freeware_brushes.push_back(new freeware_editor_brush("tl_wall_block_v", 32, 32));
    grim_interface_ptr->grim_load_texture("tl_crate", "tl_box_46.tga");
    freeware_brushes.push_back(new freeware_editor_brush("tl_crate", 46, 46));
    grim_interface_ptr->grim_load_texture("tl_tolmec", "tl_tolmec.tga");
    freeware_brushes.push_back(new freeware_editor_brush("tl_tolmec", 256, 256));
    freeware_brushes.push_back(new freeware_editor_brush("stains", 32, 32));
    grim_interface_ptr->grim_load_texture("tl_light", "light_128.tga");
    freeware_brushes.push_back(new freeware_editor_brush("tl_light", 128, 128));

    freeware_draw_loading_progress(.65f);
    freeware_particle_texture = grim_interface_ptr->grim_get_texture_handle("part");
    terrain_render_target = grim_interface_ptr->grim_get_texture_handle("ground");
    freeware_blood_texture = grim_interface_ptr->grim_get_texture_handle("stains");
    freeware_creature_texture = grim_interface_ptr->grim_get_texture_handle("goblin");
    freeware_player_texture = grim_interface_ptr->grim_get_texture_handle("ugluk");
    freeware_bullet_texture = grim_interface_ptr->grim_get_texture_handle("bullet");
    freeware_ice_texture = grim_interface_ptr->grim_get_texture_handle("icemold");
    freeware_draw_loading_progress(.75f);
    freeware_bullet_icon = grim_interface_ptr->grim_get_texture_handle("bullet_i");
    aim64_texture = grim_interface_ptr->grim_get_texture_handle("aim64");
    world_arrow_marker_texture = grim_interface_ptr->grim_get_texture_handle("arrow");
    grim_interface_ptr->grim_set_config_var(0x10, s_empty_string);
    freeware_draw_loading_progress(1.0f);

    memset(freeware_main_labels, 0, sizeof(freeware_main_labels));
    memset(freeware_option_labels, 0, sizeof(freeware_option_labels));
    freeware_main_labels[0] = strdup_malloc("Begin game.");
    freeware_main_labels[1] = strdup_malloc("Players: one");
    freeware_main_labels[2] = strdup_malloc("Game mode: career");
    freeware_main_labels[3] = strdup_malloc("Highscores.");
    freeware_main_labels[4] = strdup_malloc("Credits.");
    freeware_main_labels[5] = strdup_malloc("Options.");
    freeware_main_labels[6] = strdup_malloc("End.");
    freeware_option_labels[0] = strdup_malloc("Configure for: Player 1");
    freeware_option_labels[1] = strdup_malloc("Control method: kb static");
    freeware_option_labels[2] = strdup_malloc("Aiming device: mouse");
    freeware_option_labels[3] = strdup_malloc("Music: on");
    freeware_option_labels[4] = strdup_malloc("Background filter: smooth");
    freeware_option_labels[5] = strdup_malloc("Show FPS: off");
    freeware_option_labels[6] = strdup_malloc("Glow, Smoke & Shadow FX: off");
    freeware_option_labels[7] = strdup_malloc("Shell marks: off");
    freeware_option_labels[8] = strdup_malloc("Redefine controls");
    freeware_option_labels[9] = strdup_malloc("Calibrate joystic");
    freeware_option_labels[10] = strdup_malloc("Done");

    freeware_current_map = new freeware_level_map;
    freeware_current_map->clear();
    gameplay_reset_state();
    freeware_score_key_init();
    grim_interface_ptr->grim_set_config_var(0x12, true);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    perks_init_database();
    effect_uv_tables_init();
    SYSTEMTIME date;
    GetLocalTime(&date);
    if (date.wMonth == 8 && date.wDay >= 1 && date.wDay <= 4)
        freeware_assembly_sequence = 8;
    if (date.wMonth == 9 && date.wDay == 12)
        freeware_birthday = 1;
    LARGE_INTEGER counter;
    counter.QuadPart = date.wMilliseconds;
    QueryPerformanceCounter(&counter);
    crt_srand(counter.LowPart);
    freeware_simulation_clock = 0.0f;
    grim_interface_ptr->grim_apply_settings();

    freeware_save_config();
    freeware_brush_clear();
    delete freeware_current_map;
    for (int menu = 0; menu < 7; ++menu) {
        if (freeware_main_labels[menu])
            crt_free(freeware_main_labels[menu]);
    }
    for (int option = 0; option < 11; ++option) {
        if (freeware_option_labels[option])
            crt_free(freeware_option_labels[option]);
    }
    audio_shutdown_all();
    grim_interface_ptr->grim_shutdown();
    grim_interface_ptr->grim_release();
    return 0;
}
