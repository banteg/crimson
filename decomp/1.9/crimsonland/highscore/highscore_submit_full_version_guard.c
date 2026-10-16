#include "crimsonland_highscore.h"

unsigned char highscore_submit_full_version_guard(highscore_record_t *record)
{
    if (!highscore_record_is_valid(record)) {
        console_printf(
            &console_log_queue,
            "Potentially illegal score detected.\n");
    }

    return 1;
}
