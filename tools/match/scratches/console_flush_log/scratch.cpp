#include <stdio.h>
#include <string.h>

#include "crimsonland_console.h"

extern "C" char *game_build_path(char *filename);
extern "C" FILE *crt_fopen(char *path, char *mode);
extern "C" unsigned int crt_fwrite(
    void *ptr, unsigned int size, unsigned int count, FILE *fp);
extern "C" int crt_fflush(FILE *fp);
extern "C" int crt_fclose(FILE *fp);

unsigned char console_queue_t::flush_log(char *filename)
{
    FILE *fp = crt_fopen(game_build_path(filename), "wt");
    if (fp == 0) {
        return 0;
    }

    for (int index = log_count - 1; index >= 0; --index) {
        console_log_node_t *entry = log_head;
        for (int remaining = index; remaining > 0; --remaining) {
            entry = entry->next;
        }
        crt_fwrite(entry->text, strlen(entry->text), 1, fp);
    }
    crt_fflush(fp);
    crt_fclose(fp);
    return 1;
}
