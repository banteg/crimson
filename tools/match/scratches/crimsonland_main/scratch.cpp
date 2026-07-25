#include <string.h>
#include <urlmon.h>
#include <windows.h>

#include "crimsonland_console.h"
#include "crimsonland_types.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern crimson_cfg_t config_blob;
extern player_state_t player_state_table[2];
extern char registry_key_status_root_path[];
extern int time_played_ms;
extern char game_base_path[];
extern char key_char_buffer[];
extern int key_char_count;
extern int key_char_buffer_size;
extern char *runtime_empty_string_copy;

extern unsigned char grim_config_invoked;
extern unsigned char terrain_texture_failed;
extern unsigned char sfx_init_disabled;
extern unsigned char update_notice_pending;
extern char *update_notice_url;
extern int online_sync_status;
extern int startup_integrity_cookie;
extern unsigned char music_disabled_runtime;
extern float screen_width_f;
extern float screen_height_f;

unsigned int FUN_004623b2(void *timer);
void crt_srand(unsigned int seed);
char *crt_getcwd(char *buffer, int size);

HRESULT dx_get_version(
    int *version,
    char *version_text,
    int version_text_size);
IUnknown *WINAPI Direct3DCreate8(unsigned int sdk_version);

void config_ensure_file(void);
bool config_load_presets(bool skip_grim_settings);
bool config_sync_from_grim(void);
void game_load_status(void);
void game_sequence_load(void);
void game_save_status(void);
void register_core_cvars(void);
void init_audio_and_terrain(void);
unsigned char audio_resume_all(void);
unsigned char audio_suspend_all(void);
void audio_shutdown_all(void);
void crt_free(void *ptr);

IGrim2D_cpp *grim_load_interface(char *dll_name);
int texture_get_or_load(char *name, char *path);
int reg_write_dword(HKEY key, char *name, unsigned int value);

unsigned char game_startup_init(void);
void console_cmd_set_gamma_ramp(void);
void console_cmd_snd_add_game_tune(void);
void console_cmd_generate_terrain(void);
void console_cmd_tell_time_survived(void);
void console_cmd_set_resource_paq(void);
void console_cmd_load_texture(void);
void console_cmd_open_url(void);
void console_cmd_snd_freq_adjustment(void);
}

extern "C" int WINAPI crimsonland_main(
    HINSTANCE instance,
    HINSTANCE previous_instance,
    LPSTR command_line,
    int show_command)
{
    int directx_version;
    char directx_version_text[10];
    HKEY status_key;

    (void)instance;
    (void)previous_instance;
    (void)command_line;
    (void)show_command;

    crt_srand(FUN_004623b2(0));

    directx_version = 0;
    HRESULT directx_status = dx_get_version(
        &directx_version,
        directx_version_text,
        sizeof(directx_version_text));
    if (directx_status >= 0) {
        if ((unsigned int)directx_version < 0x80100) {
            if (MessageBoxA(
                    0,
                    "\nDirectX8.1 or newer not detected.\n\n"
                    "Crimsonland needs Microsoft DirectX 8.1 installed on the system to run.\n"
                    "It is available for download at http://www.microsoft.com/directx\n\n"
                    "Would you like to open your browser at location you can download DirectX?\n\n",
                    "Crimsonland",
                    0x23) == IDYES) {
                WCHAR browser_target[512];
                MultiByteToWideChar(
                    0,
                    0,
                    "http://www.microsoft.com/windows/directx/default.aspx",
                    -1,
                    browser_target,
                    0x104);
                if (HlinkNavigateString(0, browser_target) < 0) {
                    MessageBoxA(
                        0,
                        "Failed to launch web browser.",
                        "Crimsonland",
                        MB_OK);
                }
            }
            return 0;
        }
    } else {
        if (MessageBoxA(
                0,
                "Unknown DirectX version detected. You need to have DirectX version 8.1 or newer\n"
                "to run Crimsonland.\n\nWould you like to try and run the game anyway?",
                "Crimsonland",
                MB_YESNO) == IDNO) {
            return 0;
        }
    }

    crt_getcwd(game_base_path, 0x103);
    GetCommandLineA();
    startup_integrity_cookie = 0x7b;

    IUnknown *direct3d = Direct3DCreate8(0xdc);
    console_printf(&console_log_queue, "Crimsonland\n");
    console_printf(&console_log_queue, "-----------\n");
    console_printf(&console_log_queue, "\n");
    console_log_queue.flush_log("console.log");
    if (direct3d == 0) {
        MessageBoxA(
            0,
            "DirectX8.1 not detected.\n\n"
            "Crimsonland needs Microsoft DirectX 8.1 installed\n"
            "on the system. It is available for download at\n"
            "http://www.microsoft.com/directx",
            "Crimsonland",
            MB_OK);
        return 0;
    }
    direct3d->Release();

    console_printf(
        &console_log_queue,
        "Game base path: '%s'\n",
        game_base_path);
    console_log_queue.flush_log("console.log");

    config_ensure_file();
    console_log_queue.console_register_command(
        "setGammaRamp", console_cmd_set_gamma_ramp);
    console_log_queue.console_register_command(
        "snd_addGameTune", console_cmd_snd_add_game_tune);
    console_log_queue.console_register_command(
        "generateterrain", console_cmd_generate_terrain);
    console_log_queue.console_register_command(
        "telltimesurvived", console_cmd_tell_time_survived);
    console_log_queue.console_register_command(
        "setresourcepaq", console_cmd_set_resource_paq);
    console_log_queue.console_register_command(
        "loadtexture", console_cmd_load_texture);
    console_log_queue.console_register_command(
        "openurl", console_cmd_open_url);
    console_log_queue.console_register_command(
        "sndfreqadjustment", console_cmd_snd_freq_adjustment);

    memset(registry_key_status_root_path, 0, 0xff);
    registry_key_status_root_path[0] = 'S';
    registry_key_status_root_path[1] = 'o';
    registry_key_status_root_path[2] = 'f';
    registry_key_status_root_path[3] = 't';
    registry_key_status_root_path[4] = 'w';
    registry_key_status_root_path[5] = 'a';
    registry_key_status_root_path[6] = 'r';
    registry_key_status_root_path[7] = 'e';
    registry_key_status_root_path[8] = '\\';
    registry_key_status_root_path[9] = 'S';
    registry_key_status_root_path[10] = 'o';
    registry_key_status_root_path[11] = 'c';
    registry_key_status_root_path[12] = 'k';

    grim_interface_ptr =
        grim_load_interface("..\\grim_grSystem_c\\Release\\grim.dll");
    console_printf(&console_log_queue, "----------------------\n");
    console_printf(&console_log_queue, "----- Grim2D API -----\n");
    console_printf(&console_log_queue, "----------------------\n");
    console_printf(&console_log_queue, "Initiating Grim\n");
    console_log_queue.flush_log("console.log");
    registry_key_status_root_path[13] = 'e';
    registry_key_status_root_path[14] = 't';
    registry_key_status_root_path[15] = 'P';
    registry_key_status_root_path[16] = 'l';
    registry_key_status_root_path[17] = 'u';
    registry_key_status_root_path[18] = 'g';
    registry_key_status_root_path[19] = 'i';
    registry_key_status_root_path[20] = 'n';
    registry_key_status_root_path[21] = 's';
    registry_key_status_root_path[22] = '\\';
    registry_key_status_root_path[23] = 'D';
    registry_key_status_root_path[24] = 'e';
    registry_key_status_root_path[25] = 'f';
    registry_key_status_root_path[26] = 'a';
    registry_key_status_root_path[27] = 'u';
    registry_key_status_root_path[28] = 'l';
    registry_key_status_root_path[29] = 't';
    registry_key_status_root_path[30] = '\\';

    if (grim_interface_ptr == 0) {
        console_printf(
            &console_log_queue,
            "...DEV dll not found, trying to find REL dll\n");
        grim_interface_ptr = grim_load_interface("grim.dll");
        console_log_queue.flush_log("console.log");
    }
    if (grim_interface_ptr == 0) {
        MessageBoxA(
            0,
            "Grim.dll is corrupted or missing.\n\n"
            "(You also might have too old\n"
            "DirectX version installed. Try\n"
            "(re)installing DX8.1 or above)",
            "Grim",
            MB_OK);
        return 0;
    }

    console_printf(&console_log_queue, "...interface created\n");
    console_printf(&console_log_queue, "...registering core variables\n");
    register_core_cvars();
    if (startup_integrity_cookie != 0x7b) {
        grim_interface_ptr = 0;
    }
    console_log_queue.flush_log("console.log");

    console_printf(&console_log_queue, "...loading config pre-sets\n");
    config_load_presets(false);
    game_load_status();
    game_sequence_load();
    console_log_queue.flush_log("console.log");

    console_printf(&console_log_queue, "...invoking grim config\n");
    console_log_queue.flush_log("console.log");
    bool config_applied = grim_interface_ptr->grim_apply_config();
    grim_config_invoked = 1;
    if (!config_applied) {
        config_sync_from_grim();
        grim_config_invoked = 0;
        grim_interface_ptr->grim_release();
        return 0;
    }
    config_sync_from_grim();
    grim_config_invoked = 0;
    config_load_presets(true);

    console_printf(&console_log_queue, "...setting system states\n");
    console_log_queue.flush_log("console.log");

    terrain_texture_failed =
        grim_interface_ptr->grim_get_config_var(0x54);
    sfx_init_disabled =
        grim_interface_ptr->grim_get_config_var(0x53);
    config_blob.texture_scale =
        *(float *)grim_interface_ptr->grim_get_config_var(0x59).words;
    if (config_blob.texture_scale != 0.5f
        && config_blob.texture_scale != 1.0f
        && config_blob.texture_scale != 2.0f
        && config_blob.texture_scale != 4.0f) {
        config_blob.texture_scale = 1.0f;
    }
    config_blob.sound_disabled = sfx_init_disabled;
    config_blob.windowed =
        grim_interface_ptr->grim_get_config_var(8);

    if (terrain_texture_failed) {
        console_printf(
            &console_log_queue,
            "...using SAFEMODE fallback backend\n");
    } else {
        console_printf(
            &console_log_queue,
            "...using PRIMARY backend\n");
    }
    if (grim_interface_ptr == 0) {
        console_printf(
            &console_log_queue,
            "...using DEVELOPER backend\n");
    }
    console_log_queue.flush_log("console.log");

    grim_interface_ptr->grim_set_config_var(
        0x2d, (char *)game_startup_init);
    grim_interface_ptr->grim_set_config_var(
        5, (char *)audio_suspend_all);
    grim_interface_ptr->grim_set_config_var(
        6, (char *)audio_resume_all);
    grim_interface_ptr->grim_set_config_var(0x42, true);

    console_printf(&console_log_queue, "...setting system states\n");
    grim_interface_ptr->grim_set_config_var(7, "Crimsonland");

    config_blob.screen_width =
        grim_interface_ptr->grim_get_config_var(0x29).words[0];
    config_blob.screen_height =
        grim_interface_ptr->grim_get_config_var(0x2a).words[0];
    if (config_blob.windowed) {
        console_printf(
            &console_log_queue,
            "...selected windowed mode, window size %dx%d",
            config_blob.screen_width,
            config_blob.screen_height);
    } else {
        console_printf(
            &console_log_queue,
            "...selected fullscreen mode %dx%dx%d",
            config_blob.screen_width,
            config_blob.screen_height,
            config_blob.display_bpp);
    }

    music_disabled_runtime = config_blob.music_disabled;
    grim_interface_ptr->grim_set_config_var(0xb, true);
    console_printf(&console_log_queue, "...using keyboard\n");
    grim_interface_ptr->grim_set_config_var(0xc, true);
    console_printf(&console_log_queue, "...using mouse\n");
    grim_interface_ptr->grim_set_config_var(0xe, true);
    console_printf(&console_log_queue, "...using joystick\n");
    console_printf(&console_log_queue, "...initiating Grim system\n");

    if (!grim_interface_ptr->grim_init_system()) {
        console_printf(&console_log_queue, "Critical failure.\n");
        MessageBoxA(
            0,
            grim_interface_ptr->grim_get_error_text(),
            "Crimsonland:",
            MB_OK);
        grim_interface_ptr->grim_release();
        return 0;
    }

    console_log_queue.exec_line("exec autoexec.txt");
    grim_interface_ptr->grim_set_config_var(0x12, true);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);
    grim_interface_ptr->grim_set_config_var(0x18, 1.0f);

    screen_width_f = (float)config_blob.screen_width;
    screen_height_f = (float)config_blob.screen_height;
    console_cvar_entry_t *width_cvar =
        console_log_queue.console_register_cvar(
            "v_width", "800");
    width_cvar->value = (float)config_blob.screen_width;
    console_cvar_entry_t *height_cvar =
        console_log_queue.console_register_cvar(
            "v_height", "600");
    height_cvar->value = (float)config_blob.screen_height;

    init_audio_and_terrain();
    grim_interface_ptr->grim_set_config_var(0x10, "crimson.paq");
    console_printf(
        &console_log_queue,
        "Set resource paq to 'crimson.paq'\n");
    texture_get_or_load("backplasma", "load\\backplasma.jaz");
    texture_get_or_load("mockup", "load\\mockup.jaz");
    texture_get_or_load("logo_esrb", "load\\esrb_mature.jaz");
    texture_get_or_load("loading", "load\\loading.jaz");
    texture_get_or_load("cl_logo", "load\\logo_crimsonland.tga");

    grim_interface_ptr->grim_clear_color(0.0f, 0.0f, 0.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x36, true);
    grim_interface_ptr->grim_clear_color(0.0f, 0.0f, 0.0f, 1.0f);
    grim_interface_ptr->grim_set_config_var(0x36, true);
    grim_interface_ptr->grim_clear_color(0.0f, 0.0f, 0.0f, 1.0f);

    key_char_count = 0;
    memset(key_char_buffer, 0, key_char_buffer_size);
    grim_interface_ptr->grim_set_key_char_buffer(
        (unsigned char *)key_char_buffer,
        &key_char_count,
        key_char_buffer_size);

    config_sync_from_grim();
    for (int player_index = 0; player_index < 2; ++player_index) {
        player_input_config_t *bindings =
            &config_blob.input_config[player_index];
        player_input_t *input =
            &player_state_table[player_index].input;
        input->move_key_forward = bindings->move_key_forward;
        input->move_key_backward = bindings->move_key_backward;
        input->turn_key_left = bindings->turn_key_left;
        input->turn_key_right = bindings->turn_key_right;
        input->fire_key = bindings->fire_key;
        input->key_reserved_0 = bindings->key_reserved_0;
        input->key_reserved_1 = bindings->key_reserved_1;
        input->aim_key_left = bindings->aim_key_left;
        input->aim_key_right = bindings->aim_key_right;
        input->axis_aim_y = bindings->axis_aim_y;
        input->axis_aim_x = bindings->axis_aim_x;
        input->axis_move_y = bindings->axis_move_y;
        input->axis_move_x = bindings->axis_move_x;
    }

    grim_interface_ptr->grim_apply_settings();

    if (RegCreateKeyExA(
            HKEY_CURRENT_USER,
            "Software\\10tons entertainment\\Crimsonland",
            0,
            0,
            0,
            KEY_ALL_ACCESS,
            0,
            &status_key,
            0) == ERROR_SUCCESS) {
        reg_write_dword(
            status_key,
            "timePlayed",
            (unsigned int)time_played_ms);
        RegCloseKey(status_key);
    } else {
        console_printf(&console_log_queue, "Kameli was NOT hairy.\n");
    }

    game_save_status();
    console_printf(&console_log_queue, "Leaving Crimsonland..\n");
    if (runtime_empty_string_copy != 0) {
        crt_free(runtime_empty_string_copy);
    }
    console_log_queue.flush_log("console.log");

    audio_shutdown_all();
    console_printf(&console_log_queue, "Shutdown Grim..\n");
    grim_interface_ptr->grim_shutdown();
    console_log_queue.flush_log("console.log");
    grim_interface_ptr->grim_release();
    console_printf(
        &console_log_queue,
        "Waving the Grim Reaper goodbye..\n");
    console_log_queue.flush_log("console.log");

    if (online_sync_status == 0
        && update_notice_pending
        && update_notice_url != 0) {
        Sleep(200);
        WCHAR browser_target[512] = {0};
        MultiByteToWideChar(
            0,
            MB_PRECOMPOSED,
            update_notice_url,
            (int)strlen(update_notice_url),
            browser_target,
            0x1ff);
        if (HlinkNavigateString(0, browser_target) < 0) {
            console_printf(
                &console_log_queue,
                "Failed to open browser at '%s'.\n",
                update_notice_url);
        }
        update_notice_pending = 0;
        console_log_queue.flush_log("console.log");
    }

    return 0;
}
