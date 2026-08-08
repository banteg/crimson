#include <windows.h>

#include "crimsonland_gameplay.h"

unsigned int reg_read_dword_default(
    HKEY key,
    char *name,
    unsigned int *out,
    unsigned int fallback);

void play_time_load(void)
{
    HKEY key;
    unsigned int stored_play_time_ms;

    if (RegCreateKeyExA(
            HKEY_LOCAL_MACHINE,
            registry_key_status_root_path,
            0,
            0,
            0,
            KEY_ALL_ACCESS,
            0,
            &key,
            0)
        == ERROR_SUCCESS) {
        reg_read_dword_default(key, "sequence", &stored_play_time_ms, 0);
        if (play_time_ms < stored_play_time_ms) {
            play_time_ms = stored_play_time_ms;
        }
        RegCloseKey(key);
    }
}
