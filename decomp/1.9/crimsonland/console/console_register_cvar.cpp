#include "crimsonland_console.h"

extern "C" void crt_free(void *ptr);
extern "C" double crt_atof_l(char *text);

inline console_cvar_entry_t::console_cvar_entry_t(char *entry_name)
{
    mod_id = 0;
    mod_string_value = 0;
    mod_float_value = 0;
    name = strdup_malloc(entry_name);
    next = 0;
    unknown_08 = 0;
    value = 0.0f;
    string_value = 0;
    unknown_14 = 0;
}

console_cvar_entry_t *console_queue_t::console_register_cvar(
    char *name,
    char *value_text)
{
    console_cvar_entry_t *entry = console_cvar_find(name);
    if (entry != 0) {
        if (entry->string_value != 0) {
            crt_free(entry->string_value);
        }
        entry->string_value = 0;
        entry->string_value = strdup_malloc(value_text);
        entry->value = (float)crt_atof_l(value_text);
        return entry;
    }

    if (cvar_head != 0) {
        console_cvar_entry_t *tail = cvar_head;
        while (tail->next != 0) {
            tail = tail->next;
        }
        tail->next = new console_cvar_entry_t(name);
        tail->next->string_value = strdup_malloc(value_text);
        tail->next->value = (float)crt_atof_l(value_text);
        return tail->next;
    }

    cvar_head = new console_cvar_entry_t(name);
    cvar_head->string_value = strdup_malloc(value_text);
    cvar_head->value = (float)crt_atof_l(value_text);
    return cvar_head;
}
