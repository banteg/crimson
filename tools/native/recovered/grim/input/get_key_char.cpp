#include "grim2d_cpp.h"

extern int grim_key_char_queue[8];
extern int grim_key_char_queue_count;

int IGrim2D_cpp::grim_get_key_char(void)
{
    int count = grim_key_char_queue_count;
    if (count == 0) {
        return 0;
    }
    int result = grim_key_char_queue[0];
    if (count > 0) {
        int *cursor = grim_key_char_queue;
        int remaining = count;
        do {
            int value = cursor[1];
            cursor[0] = value;
            ++cursor;
            --remaining;
        } while (remaining != 0);
    }
    grim_key_char_queue_count = count - 1;
    return result;
}
