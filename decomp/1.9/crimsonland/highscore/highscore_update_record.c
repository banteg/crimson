#include <stdio.h>
#include <string.h>

#include "crimsonland_highscore.h"

extern char default_player_name[];

int crt_rand(void);
char *highscore_read_record(char *buffer, FILE *fp);
void highscore_write_record(highscore_record_t *record, FILE *fp);

unsigned char highscore_update_record(
    char *path,
    highscore_record_t *record)
{
    highscore_record_t stored;
    FILE *fp;

    memset(&stored, 0, sizeof(stored));
    strcpy(stored.player_name, default_player_name);
    stored.flags = 0;
    stored.sentinel_pipe = '|';
    stored.sentinel_ff = 0xff;
    stored.random_tag = crt_rand() & 0x0fee050f;

    fp = fopen(path, "r+b");
    if (fp == 0) {
        return 0;
    }

    while (!feof(fp)) {
        if (highscore_read_record((char *)&stored, fp) != 0 &&
            highscore_record_equals(record, &stored)) {
            if ((stored.flags & 2) != 0) {
                fclose(fp);
                return 1;
            }
            if (stored.flags == 0) {
                record->flags = 2;
            }
            fseek(fp, -(long)(sizeof(stored) + sizeof(int)), SEEK_CUR);
            highscore_write_record(record, fp);
            fflush(fp);
            fclose(fp);
            return 1;
        }
    }

    fflush(fp);
    fclose(fp);
    return 0;
}
