#include "crimsonland_console.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *grim_interface_ptr;

void console_queue_t::console_set_open(unsigned char value)
{
    open = value;
#if CL_BUILD >= 10900
    console_input_enabled = value;
    grim_interface_ptr->grim_flush_input();
#endif
}
