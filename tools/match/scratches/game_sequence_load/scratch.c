#include <windows.h>

#include "crimsonland_gameplay.h"

unsigned int reg_read_dword_default(
    HKEY key,
    char *name,
    unsigned int *out,
    unsigned int fallback);

void game_sequence_load(void)
{
    HKEY key;
    unsigned int sequence;

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
        reg_read_dword_default(key, "sequence", &sequence, 0);
        if (game_sequence_id < sequence) {
            game_sequence_id = sequence;
        }
        RegCloseKey(key);
    }
}
