#ifndef CRIMSONLAND_CONSOLE_H
#define CRIMSONLAND_CONSOLE_H

#ifdef __cplusplus

extern "C" char *strdup_malloc(char *src);

struct console_cvar_entry_t {
    char *name;
    console_cvar_entry_t *next;
    int unknown_08;
    float value;
    char *string_value;
    int unknown_14;
    char *mod_id;
    char *mod_string_value;
    float *mod_float_value;

    console_cvar_entry_t(char *entry_name);
    ~console_cvar_entry_t(void);
};

struct console_history_entry_t {
    char *line;
    console_history_entry_t *next;

    console_history_entry_t(void);
    ~console_history_entry_t(void);
    console_history_entry_t *release(unsigned char free_self);
};

struct console_log_node_t {
    char *text;
    console_log_node_t *next;

    console_log_node_t(void);
    ~console_log_node_t(void);
    console_log_node_t *release(unsigned char free_self);
};

struct console_command_entry_t {
    char *name;
    console_command_entry_t *next;
    void (*handler)(void);

    console_command_entry_t(char *entry_name)
        : name(strdup_malloc(entry_name)), next(0), handler(0) {}
    ~console_command_entry_t(void);
};

struct console_queue_t {
    console_cvar_entry_t *cvar_head;
    console_command_entry_t *command_head;
    console_log_node_t *log_head;
    unsigned char echo_enabled;
    unsigned char _pad0[3];
    console_history_entry_t *history_head;
    int history_index;
    int height;
    float slide_y;
    int log_count;
    int scroll_offset;
    unsigned char open;

    console_queue_t(void);
    ~console_queue_t(void);

    void console_push_line(char *line);
    unsigned char flush_log(char *filename);
    bool exec_line(char *line);
    void console_set_open(unsigned char open);
    void console_history_apply(void);
    console_cvar_entry_t *console_cvar_find(char *name);
    console_command_entry_t *console_command_find(char *name);
    char *console_cvar_autocomplete(char *prefix);
    char *console_command_autocomplete(char *prefix);
    console_cvar_entry_t *console_register_cvar(char *name, char *value);
    unsigned char console_cvar_unregister(char *name);
    void console_register_command(char *name, void (*handler)(void));
    unsigned char console_command_unregister(char *name);
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
extern char console_exec_line_buf[512];
extern char console_tokenize_buf[];
extern char console_format_buffer[512];
extern int console_cmd_argc;
extern unsigned char console_input_enabled;

char *console_cmd_arg_get(int index);
void console_printf(console_queue_t *queue, char *format, ...);
int crt_vsprintf(char *dst, char *format, void *args);

#ifdef __cplusplus
}
#endif

#endif
