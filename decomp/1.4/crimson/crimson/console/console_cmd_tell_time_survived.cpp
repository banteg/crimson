#include "crimsonland_gameplay.h"

extern "C" void console_cmd_tell_time_survived(void)
{
    console_printf(
        &console_log_queue,
        "Survived: %i seconds.\n",
        (double)*(float *)&run_elapsed_ms);
}
