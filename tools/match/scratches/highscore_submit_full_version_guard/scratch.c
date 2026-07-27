#include "crimsonland_highscore.h"

unsigned char game_is_full_version();

unsigned char highscore_submit_full_version_guard(highscore_record_t *record)
{
    if (!game_is_full_version(record)) {
        console_printf(
            &console_log_queue,
            "Potentially illegal score detected.\n");
    }

    return 1;
}
