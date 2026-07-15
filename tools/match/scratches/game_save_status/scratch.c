#include <stdio.h>
#include <windows.h>

#include "crimsonland_gameplay.h"

extern game_status_t game_status_blob;

int reg_write_dword(HKEY key, char *name, unsigned int value);
char *game_build_path(char *filename);
FILE *crt_fopen(char *path, char *mode);
unsigned int crt_fwrite(
    void *ptr, unsigned int size, unsigned int count, FILE *fp);
int crt_fclose(FILE *fp);
void game_load_status(void);
void game_sequence_load(void);

void game_save_status(void)
{
    HKEY key;
    int checksum;
    FILE *fp;
    unsigned int sequence;
    int index;
    int key_step;
    char *status_bytes;
    char value;
    int signed_value;
    int term;
    char encoded;

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
        sequence = game_sequence_id;
        reg_write_dword(key, "sequence", sequence);
        reg_write_dword(key, "dataPathId", (sequence * 13 + 3) >> 1);
        reg_write_dword(key, "transferFailed", 0);
        RegCloseKey(key);
    }

    fp = crt_fopen(game_build_path("game.cfg"), "wb");
    if (fp != 0) {

        game_status_blob.quest_unlock_index = (unsigned short)quest_unlock_index;
        game_status_blob.quest_unlock_index_full =
            (unsigned short)quest_unlock_index_full;

        checksum = 0;
        index = 0;
        key_step = 0;
        status_bytes = (char *)&game_status_blob;
        do {
            value = status_bytes[index];
            signed_value = value;
            term = signed_value * 7;
            term += index;
            term *= signed_value;
            term += key_step;
            checksum += term + 13;

            key_step += 111;
            encoded = (char)index;
            encoded *= 7;
            encoded += 15;
            encoded *= (char)index;
            encoded += 3;
            encoded *= (char)index;
            encoded += value;
            encoded += 111;
            status_bytes[index] = encoded;
            ++index;
        } while ((unsigned int)key_step < 0x10b18);

        crt_fwrite(&game_status_blob, sizeof(game_status_blob), 1, fp);
        crt_fwrite(&checksum, sizeof(checksum), 1, fp);
        crt_fclose(fp);

        if (cv_verbose->value != 0.0f) {
            console_printf(&console_log_queue, "GAME_SaveStatus OK.\n");
        }
        game_load_status();
        game_sequence_load();
        game_sequence_load();
        return;
    }

    console_printf(&console_log_queue, "GAME_SaveStatus FAILED!\n");
    game_sequence_load();
}
