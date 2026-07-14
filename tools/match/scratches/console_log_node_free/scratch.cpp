#include "crimsonland_console.h"

extern "C" void crt_free(void *ptr);

console_log_node_t *console_log_node_t::release(unsigned char free_self)
{
    if (text != 0) {
        crt_free(text);
    }
    text = 0;

    if (next != 0) {
        next->release(1);
    }
    next = 0;

    if ((free_self & 1) != 0) {
        crt_free(this);
    }
    return this;
}
