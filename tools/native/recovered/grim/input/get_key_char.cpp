#include "grim2d_cpp.h"

extern int grim_key_char_queue[8];
extern int grim_key_char_queue_count;

int IGrim2D_cpp::grim_get_key_char(void)
{
    if (grim_key_char_queue_count == 0) {
        return 0;
    }
    int result = grim_key_char_queue[0];
    for (int i = 0; i < grim_key_char_queue_count; ++i) {
        grim_key_char_queue[i] = grim_key_char_queue[i + 1];
    }
    --grim_key_char_queue_count;
    return result;
}
