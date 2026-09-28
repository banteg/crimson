#include <string.h>

#include "crimsonland_gameplay.h"

int highscore_init_sentinels(void)
{
    highscore_record_t *record = highscore_table;
    int count = 100;
    int result;

    do {
        memset(record, 0, sizeof(*record));
        strcpy(record->player_name, default_player_name);
        record->flags = 0;
        record->sentinel_pipe = '|';
        record->sentinel_ff = 0xff;
        result = crt_rand() & 0x0fee050f;
        record->random_tag = result;
        ++record;
    } while (--count != 0);

    return result;
}
