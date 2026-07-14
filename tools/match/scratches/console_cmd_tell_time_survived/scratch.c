#include "crimsonland_gameplay.h"

void console_cmd_tell_time_survived(void)
{
    console_printf(
        &console_log_queue,
        "Survived: %i seconds.\n",
        (int)((float)survival_elapsed_ms * 0.00100000005f));
}
