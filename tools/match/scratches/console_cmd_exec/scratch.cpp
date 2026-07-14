#include <stdio.h>
#include <string.h>

#include "crimsonland_console.h"

extern "C" FILE *crt_fopen(char *path, char *mode);
extern "C" char *crt_fgets(char *dst, int dst_len, FILE *fp);
extern "C" int crt_fclose(FILE *fp);

extern "C" void console_cmd_exec(void)
{
    if (console_cmd_argc != 2) {
        console_printf(&console_log_queue, "exec <script>\n");
        return;
    }

    FILE *fp = crt_fopen(console_cmd_name[1], "rt");
    if (fp == 0) {
        console_printf(
            &console_log_queue,
            "Cannot open file '%s'\n",
            console_cmd_name[1]);
        return;
    }

    console_printf(
        &console_log_queue,
        "Executing '%s'\n",
        console_cmd_name[1]);
    while (crt_fgets(console_exec_line_buf, 511, fp) != 0) {
        char *newline = strchr(console_exec_line_buf, '\n');
        if (newline != 0) {
            *newline = 0;
        }
        console_exec_line_buf[511] = 0;
        if (console_exec_line_buf[0] != '/'
            && console_exec_line_buf[1] != '/'
            && console_exec_line_buf[0] != '\n'
            && console_exec_line_buf[0] != 0
            && console_exec_line_buf[0] != '#') {
            console_log_queue.exec_line(console_exec_line_buf);
        }
    }
    crt_fclose(fp);
}
