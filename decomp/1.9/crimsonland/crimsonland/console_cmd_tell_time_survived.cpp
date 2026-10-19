#include "crimsonland_gameplay.h"

extern "C" void console_cmd_tell_time_survived(void)
{
#if CL_BUILD < 10900
    console_printf(
        &console_log_queue,
        "Survived: %i seconds.\n",
        (double)*(float *)&run_elapsed_ms);
#else
    console_printf(
        &console_log_queue,
        "Survived: %i seconds.\n",
        (int)((float)run_elapsed_ms * 0.00100000005f));
#endif
}
