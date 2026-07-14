#ifndef CRIMSONLAND_CONSOLE_H
#define CRIMSONLAND_CONSOLE_H

#ifdef __cplusplus

struct console_cvar_entry_t {
    char *name;
    console_cvar_entry_t *next;
};

struct console_queue_t {
    console_cvar_entry_t *cvar_head;
    void *command_head;
    void *log_head;
    unsigned char echo_enabled;
    unsigned char _pad0[0x1b];
    unsigned char open;

    bool console_push_line(char *line);
    unsigned char flush_log(char *filename);
    bool exec_line(char *line);
    void console_set_open(unsigned char open);
    console_cvar_entry_t *console_cvar_find(char *name);
};

#else

typedef struct console_queue_t console_queue_t;

#endif

extern console_queue_t console_log_queue;

#ifdef __cplusplus
extern "C" {
#endif

extern char *console_empty_arg;
extern char *console_cmd_name[];
extern char console_format_buffer[512];
extern int console_cmd_argc;
extern unsigned char console_input_enabled;

char *console_cmd_arg_get(int index);
unsigned char console_printf(console_queue_t *queue, char *format, ...);
int crt_vsprintf(char *dst, char *format, void *args);

#ifdef __cplusplus
}
#endif

#endif
