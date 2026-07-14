#include "crimsonland_console.h"
#include "grim2d_cpp.h"

extern "C" int console_cmd_argc_get(void);
extern "C" double crt_atof_l(char *text);
extern IGrim2D_cpp *grim_interface_ptr;

extern "C" void console_cmd_set_gamma_ramp(void)
{
    if (console_cmd_argc_get() != 2) {
        console_printf(&console_log_queue, "setGammaRamp <scalar > 0>\n");
        console_printf(
            &console_log_queue,
            "Command adjusts gamma ramp linearly by multiplying with given scalar\n");
        return;
    }

    float scalar = (float)crt_atof_l(console_cmd_arg_get(1));
    grim_interface_ptr->grim_set_config_var(0x1c, scalar);
    console_printf(
        &console_log_queue,
        "Gamma ramp regenerated and multiplied with %f\n",
        scalar);
}
