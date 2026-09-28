#include <windows.h>

#include "crimsonland_audio.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

extern "C" {
extern char s_empty_string[];
extern char *runtime_empty_string_copy;
extern SYSTEMTIME local_system_time;
extern unsigned char seasonal_balloon_load_active;
extern unsigned char startup_terrain_generation_active;
extern int time_played_ms;

void effect_uv_tables_init(void);
void perks_init_database(void);
void weapon_table_init(void);
unsigned char game_core_init(void);
int texture_get_or_load(char *name, char *path);
void gameplay_reset_state(void);
void terrain_generate_random(void);
int reg_read_dword_default(
    HKEY key,
    char *name,
    unsigned int *out,
    unsigned int fallback);
void crt_srand(unsigned int seed);
}

extern "C" void game_startup_init_prelude(void)
{
    runtime_empty_string_copy = strdup_malloc(s_empty_string);

    grim_interface_ptr->grim_set_config_var(0x12, true);
    grim_interface_ptr->grim_set_config_var(0x13, 5u);
    grim_interface_ptr->grim_set_config_var(0x14, 6u);

    effect_uv_tables_init();
    console_log_queue.flush_log("console.log");
    console_printf(&console_log_queue, "Entering Crimsonland..\n");
    perks_init_database();
    weapon_table_init();
    game_core_init();

    GetLocalTime(&local_system_time);
    WORD month = local_system_time.wMonth;
    if ((month == 9 && local_system_time.wDay == 12)
        || (month == 11 && local_system_time.wDay == 8)
        || (month == 12 && local_system_time.wDay == 18)) {
        seasonal_balloon_load_active = 1;
        texture_get_or_load("balloon", "balloon.tga");
    }
    seasonal_balloon_load_active = 0;
    console_printf(&console_log_queue, "Unloaded resource paq\n");

    grim_interface_ptr->grim_set_config_var(0x10, s_empty_string);

    LARGE_INTEGER counter;
    counter.QuadPart = local_system_time.wMilliseconds;
    QueryPerformanceCounter(&counter);
    crt_srand(counter.LowPart);

    gameplay_reset_state();
    startup_terrain_generation_active = 1;
    terrain_generate_random();
    startup_terrain_generation_active = 0;

    HKEY key;
    unsigned int played_ms;
    LONG result = RegCreateKeyExA(
        HKEY_CURRENT_USER,
        "Software\\10tons entertainment\\Crimsonland",
        0,
        0,
        REG_OPTION_RESERVED,
        KEY_ALL_ACCESS,
        0,
        &key,
        0);
    if (result == ERROR_SUCCESS) {
        reg_read_dword_default(key, "timePlayed", &played_ms, result);
        time_played_ms = played_ms;
        RegCloseKey(key);
    }
}
