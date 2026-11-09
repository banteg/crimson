#include <stdio.h>
#include <string.h>

#include "crimsonland_console.h"
#include "grim2d_cpp.h"

extern IGrim2D_cpp *freeware_console_grim;
extern "C" int freeware_atoi(char *text);
extern "C" FILE *crt_fopen(char *path, char *mode);
extern "C" char *crt_fgets(char *dst, int dst_len, FILE *fp);
extern "C" int crt_fclose(FILE *fp);

extern "C" void freeware_console_cmd_show(void)
{
    console_printf(&console_log_queue, "%d arguments.", console_cmd_argc);
    for (int i = 0; i < console_cmd_argc; ++i) {
        console_printf(&console_log_queue, "%d: %s", i, console_cmd_name[i]);
    }
}

extern "C" void freeware_console_cmd_count(void)
{
    if (console_cmd_argc != 4) {
        console_printf(&console_log_queue, "Not enough parameters. (eg. count 1 + 3)\n");
        return;
    }

    int left = freeware_atoi(console_cmd_name[1]);
    int right = freeware_atoi(console_cmd_name[3]);
    switch (console_cmd_name[2][0]) {
    case '+':
        console_printf(&console_log_queue, "%d + %d = %d", left, right, left + right);
        break;
    case '-':
        // The original's subtraction case also adds its operands.
        console_printf(&console_log_queue, "%d - %d = %d", left, right, left + right);
        break;
    case '*':
        console_printf(&console_log_queue, "%d * %d = %d", left, right, left * right);
        break;
    case '/':
        console_printf(&console_log_queue, "%d / %d = %d", left, right, left / right);
        break;
    default:
        console_printf(&console_log_queue, "Unknown operator '%s'", console_cmd_name[2]);
        break;
    }
}

extern "C" void freeware_console_cmd_printfile(void)
{
    if (console_cmd_argc != 2) {
        console_printf(&console_log_queue, "printfile <filename>\n");
        return;
    }

    FILE *fp = crt_fopen(console_cmd_name[1], "rt");
    if (fp == 0) {
        console_printf(&console_log_queue, "Cannot open file '%s'", console_cmd_name[1]);
        return;
    }

    while (crt_fgets(console_exec_line_buf, 511, fp) != 0) {
        char *newline = strchr(console_exec_line_buf, '\n');
        if (newline != 0) {
            *newline = 0;
        }
        console_exec_line_buf[511] = 0;
        console_log_queue.console_push_line(console_exec_line_buf);
    }
    crt_fclose(fp);
}

extern "C" void freeware_console_cmd_showfps(void)
{
    console_printf(&console_log_queue, "fps: %d", (int)freeware_console_grim->grim_get_fps());
}

extern "C" void freeware_console_cmd_state_unavailable(void)
{
    console_printf(&console_log_queue, "Crimsonland2 core engine required.\n");
}
