#include "crimsonland_console.h"
#include "crimsonland_mod_api.h"

extern "C" char console_cvar_default_true[];

mod_var_t *mod_api_cpp_t::mod_api_core_get_var(char *id)
{
    console_cvar_entry_t *entry = console_log_queue.console_cvar_find(id);
    if (!entry) {
        entry = console_log_queue.console_register_cvar(
            id, console_cvar_default_true);
    }

    entry->mod_float_value = &entry->value;
    entry->mod_id = entry->name;
    entry->mod_string_value = entry->string_value;
    return (mod_var_t *)&entry->mod_id;
}
