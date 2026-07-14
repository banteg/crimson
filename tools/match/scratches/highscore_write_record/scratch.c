#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "crimsonland_highscore.h"

extern char default_player_name[];
extern SYSTEMTIME local_system_time;

int crt_rand(void);

void highscore_write_record(highscore_record_t *record, FILE *fp)
{
    int checksum = 0;
    highscore_record_t encoded;
    unsigned int i;
    char *cursor;

    GetLocalTime(&local_system_time);

    memset(&encoded, 0, sizeof(encoded));
    strcpy(encoded.player_name, default_player_name);
    encoded.flags = 0;
    encoded.sentinel_pipe = '|';
    encoded.sentinel_ff = 0xff;
    encoded.random_tag = crt_rand() & 0x0fee050f;

    if (record->day == 0) {
        record->day = (unsigned char)local_system_time.wDay;
        record->month = (unsigned char)local_system_time.wMonth;
        record->year_offset =
            (unsigned char)(local_system_time.wYear - 2000);
        record->date_checksum = highscore_date_checksum(
            local_system_time.wYear,
            local_system_time.wMonth,
            local_system_time.wDay);
    }

    memcpy(&encoded, record, sizeof(encoded));
    cursor = (char *)&encoded;
    for (i = 0; i < sizeof(encoded); i++, cursor++) {
        checksum += (i + 3) * *cursor * 7;
    }
    for (i = 0; i < sizeof(encoded); i++) {
        ((char *)&encoded)[i] += (i * 5 + 1) * i + 6;
    }

    fwrite(&encoded, sizeof(encoded), 1, fp);
    fwrite(&checksum, sizeof(checksum), 1, fp);
}
