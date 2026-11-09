#include "crimsonland_console.h"
#include <stdio.h>
#include <string.h>

extern "C" {
extern console_queue_t freeware_console;
void freeware_score_key_init();
unsigned char freeware_score_decode(char *, int);
void freeware_score_encode(char *, int);
char *highscore_build_path();
void crt_free(void *);
}

extern "C" unsigned char freeware_score_merge(const char *source_path)
{
    freeware_score_key_init();
    FILE *dest = fopen(highscore_build_path(), "rb");
    FILE *src = fopen(source_path, "rb");
    if (!dest || !src) {
        console_printf(&freeware_console, "Could not open file.\n");
        return 0;
    }

    fseek(dest, 0, SEEK_END);
    int dest_size = ftell(dest) - 4;
    char *dest_bytes = new char[dest_size + 4];
    fseek(src, 0, SEEK_END);
    int src_size = ftell(src) - 4;
    char *src_bytes = new char[src_size + 4];

    fseek(dest, 0, SEEK_SET);
    fread(dest_bytes, dest_size + 4, 1, dest);
    fclose(dest);
    fseek(src, 0, SEEK_SET);
    fread(src_bytes, src_size + 4, 1, src);
    fclose(src);
    if (!freeware_score_decode(dest_bytes, dest_size)) {
        console_printf(&freeware_console, "Decoding %s failed.\n", highscore_build_path());
        crt_free(dest_bytes);
        crt_free(src_bytes);
        return 0;
    }
    if (!freeware_score_decode(src_bytes, src_size)) {
        console_printf(&freeware_console, "Decoding %s failed.\n", source_path);
        crt_free(dest_bytes);
        crt_free(src_bytes);
        return 0;
    }
    char *bytes = new char[dest_size + src_size + 4];
    memcpy(bytes, dest_bytes, dest_size);
    memcpy(bytes + dest_size, src_bytes, src_size);
    crt_free(dest_bytes);
    crt_free(src_bytes);
    int size = dest_size + src_size;
    freeware_score_encode(bytes, size);
    dest = fopen(highscore_build_path(), "wb");
    fseek(dest, 0, SEEK_SET);
    fwrite(bytes, size + 4, 1, dest);
    fclose(dest);
    crt_free(bytes);
    console_printf(&freeware_console, "Merged highscores %s and %s.\n", highscore_build_path(), source_path);
    return 1;
}
