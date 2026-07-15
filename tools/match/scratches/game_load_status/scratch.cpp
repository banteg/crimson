#include <stdio.h>

#include "crimsonland_gameplay.h"

extern game_status_t game_status_blob;

char *game_build_path(char *filename);
FILE *crt_fopen(char *path, char *mode);
int crt_fseek(FILE *fp, long offset, int origin);
long crt_ftell(FILE *fp);
unsigned int crt_fread(
    void *ptr, unsigned int size, unsigned int count, FILE *fp);
int crt_fclose(FILE *fp);
void game_save_status(void);
void game_sequence_load(void);

void game_load_status(void)
{
    FILE *fp;
    int checksum_file;
    int checksum;
    int index;
    int key_step;
    char *status_bytes;
    char decoded;
    unsigned char offset;
    int signed_value;
    int term;

    fp = crt_fopen(game_build_path("game.cfg"), "rb");
    key_step = 0;
    if (fp != 0) {
        crt_fseek(fp, 0, SEEK_END);
        if (crt_ftell(fp) != sizeof(game_status_blob) + sizeof(checksum_file)) {
            crt_fclose(fp);
            console_printf(
                &console_log_queue,
                "GAME_LoadStatus FAILED, invalid file size\n");
            game_sequence_load();
            return;
        }

        crt_fseek(fp, 0, SEEK_SET);
        crt_fread(&game_status_blob, sizeof(game_status_blob), 1, fp);
        checksum_file = 0;
        crt_fread(&checksum_file, sizeof(checksum_file), 1, fp);

        checksum = 0;
        index = 0;
        status_bytes = (char *)&game_status_blob;
        do {
            decoded = (char)index;
            offset = 145;
            decoded *= 7;
            decoded += 15;
            decoded *= (char)index;
            decoded += 3;
            decoded *= (char)index;
            offset -= (unsigned char)decoded;
            status_bytes[index] += offset;
            decoded = status_bytes[index];

            signed_value = decoded;
            term = signed_value * 7;
            term += index;
            term *= signed_value;
            term += key_step;
            checksum += term + 13;

            key_step += 111;
            ++index;
        } while ((unsigned int)key_step < 0x10b18);

        if (checksum != checksum_file) {
            crt_fclose(fp);
            console_printf(
                &console_log_queue,
                "GAME_LoadStatus FAILED, check sum invalid\n");
            game_sequence_load();
            return;
        }

        quest_unlock_index = game_status_blob.quest_unlock_index;
        quest_unlock_index_full = game_status_blob.quest_unlock_index_full;
        crt_fclose(fp);
        if (cv_verbose->value != 0.0f) {
            console_printf(&console_log_queue, "GAME_LoadStatus OK.\n");
        }
        return;
    }

    console_printf(&console_log_queue, "GAME_LoadStatus FAILED!\n");
    console_printf(&console_log_queue, "Generating new file..\n");
    game_status_blob.quest_unlock_index = 0;
    game_status_blob.quest_unlock_index_full = 0;
    game_sequence_load();
    game_save_status();
    game_sequence_load();
}
