#include <string.h>

#include "crimsonland_console.h"

extern "C" char *crt_strtok(char *str, char *delimiters);

void console_queue_t::console_tokenize_line(char *line)
{
    console_cmd_argc = 0;
    if (line == 0) {
        return;
    }
    if (strlen(line) >= 2 && line[0] == '/' && line[1] == '/') {
        return;
    }

    strcpy(console_tokenize_buf, line);
    char *token = crt_strtok(console_tokenize_buf, " \n");
    if (token == 0) {
        return;
    }

    console_cmd_name[0] = token;
    int argc = 1;
    char **argument = &console_cmd_name[1];
    while (true) {
        token = crt_strtok(0, " \n");
        if (token == 0) {
            break;
        }
        *argument = token;
        ++argc;
        ++argument;
    }
    console_cmd_argc = argc;
}
