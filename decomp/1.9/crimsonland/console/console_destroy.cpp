#include "crimsonland_console.h"

extern "C" void crt_free(void *ptr);

inline console_log_node_t::~console_log_node_t(void)
{
    if (text != 0) {
        crt_free(text);
    }
    text = 0;
    if (next != 0) {
        next->release(1);
    }
    next = 0;
}

inline console_cvar_entry_t::~console_cvar_entry_t(void)
{
    if (name != 0) {
        crt_free(name);
    }
    name = 0;
}

inline console_command_entry_t::~console_command_entry_t(void)
{
    if (name != 0) {
        crt_free(name);
    }
    name = 0;
}

inline console_history_entry_t::~console_history_entry_t(void)
{
    if (line != 0) {
        crt_free(line);
    }
    line = 0;
    if (next != 0) {
        next->release(1);
    }
    next = 0;
}

console_queue_t::~console_queue_t(void)
{
    delete log_head;
    log_head = 0;
    delete cvar_head;
    cvar_head = 0;
    delete command_head;
    command_head = 0;
    delete history_head;
    history_head = 0;
}
