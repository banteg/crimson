#include <string.h>

#include "crimsonland_console.h"

inline console_cvar_entry_t::console_cvar_entry_t(char *entry_name)
{
    name = strdup_malloc(entry_name);
    next = 0;
    unknown_08 = 0;
    value = 0.0f;
    string_value = 0;
    unknown_14 = 0;
}

inline console_history_entry_t::console_history_entry_t(void)
{
    next = 0;
    line = 0;
}

extern "C" char s_empty_string[];

extern "C" void console_cmdlist(void);
extern "C" void console_vars(void);
extern "C" void console_echo(void);
extern "C" void console_cmd_set(void);
extern "C" void console_cmd_quit(void);
extern "C" void console_clear_log(void);
extern "C" void console_cmd_extend(void);
extern "C" void console_cmd_minimize(void);
extern "C" void console_cmd_exec(void);

extern "C" void freeware_console_cmd_show(void);
extern "C" void freeware_console_cmd_count(void);
extern "C" void freeware_console_cmd_printfile(void);
extern "C" void freeware_console_cmd_showfps(void);
extern "C" void freeware_console_cmd_state_unavailable(void);

console_queue_t::console_queue_t(void)
{
    echo_enabled = 1;
    height = 300;
    slide_y = -300.0f;
    scroll_offset = 0;
    log_head = 0;

    cvar_head = new console_cvar_entry_t("version");
    cvar_head->value = 1.0f;
    cvar_head->string_value = strdup_malloc("0.5");
    cvar_head->unknown_14 = 1;

    memset(console_tokenize_buf, 0, 16);
    console_cmd_argc = 0;

    console_register_command("cmdlist", console_cmdlist);
    console_register_command("vars", console_vars);
    console_register_command("echo", console_echo);
    console_register_command("set", console_cmd_set);
    console_register_command("quit", console_cmd_quit);
    console_register_command("clear", console_clear_log);
    console_register_command("show", freeware_console_cmd_show);
    console_register_command("count", freeware_console_cmd_count);
    console_register_command("printfile", freeware_console_cmd_printfile);
    console_register_command("extendconsole", console_cmd_extend);
    console_register_command("minimizeconsole", console_cmd_minimize);
    console_register_command("showfps", freeware_console_cmd_showfps);
    console_register_command("exec", console_cmd_exec);
    console_register_command("savestate", freeware_console_cmd_state_unavailable);
    console_register_command("loadstate", freeware_console_cmd_state_unavailable);

    history_head = new console_history_entry_t;
    history_head->line = strdup_malloc(s_empty_string);
    history_index = 0;
}
