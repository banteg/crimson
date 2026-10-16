#ifndef CRIMSONLAND_HIGHSCORE_RECORD_H
#define CRIMSONLAND_HIGHSCORE_RECORD_H

#include <stdio.h>
#include <string.h>

#include "crimsonland_highscore.h"

extern "C" {
extern char default_player_name[];
int crt_rand(void);
unsigned char highscore_update_record(char *path, highscore_record_t *record);
void highscore_write_record(highscore_record_t *record, FILE *fp);
void highscore_load_table(void);
}

// The game's C++ reset of a scratch record, inlined through `this`. C2 9044
// (1.9.8) then copies the default name with a pointer-difference loop, as the
// native code does; a free inline helper lets it fold the frame address into
// an indexed copy instead. 1.9.93 compiles both spellings identically.
struct highscore_record_cpp_t : highscore_record_t {
    void reset_light()
    {
        memset(this, 0, sizeof(*this));
        strcpy(player_name, default_player_name);
        flags = 0;
        sentinel_pipe = '|';
        sentinel_ff = 0xff;
        random_tag = crt_rand() & 0x0fee050f;
    }
};

#endif
