#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "crimsonland_highscore.h"

extern unsigned char highscore_save_skip_record_init;

char *highscore_build_path(void);
void highscore_record_init(void);
unsigned char highscore_update_record(
    char *path,
    highscore_record_t *record);
void highscore_write_record(highscore_record_t *record, FILE *fp);

void highscore_save_record(highscore_record_t *record)
{
    char *path = highscore_build_path();
    int index;
    FILE *fp;

    if (record == 0) {
        console_printf(&console_log_queue, "UNEXPECTED: sc is null!\n");
        return;
    }

    index = strlen(record->player_name) - 1;
    while (index > 0 && record->player_name[index] == ' ') {
        record->player_name[index] = 0;
        index--;
    }

    CreateDirectoryA("scores5", 0);
    if (!highscore_save_skip_record_init) {
        highscore_record_init();
    }

    if ((record->flags & 1) != 0 && highscore_update_record(path, record)) {
        return;
    }

    fp = fopen(path, "ab");
    if (fp == 0) {
        console_printf(
            &console_log_queue,
            "Unable to save score: disk full or file in use?\n");
        return;
    }
    highscore_write_record(record, fp);
    fclose(fp);
}
