#include "grim2d_cpp.h"

extern int grim_key_char_queue[8];
extern int grim_key_char_queue_count;

int IGrim2D_cpp::grim_get_key_char(void)
{
    if (grim_key_char_queue_count == 0) {
        return 0;
    }
    int result = grim_key_char_queue[0];
#if CL_BUILD == 10908
    // 1.9.8's shift loop has an empty body, so only the slot at the old
    // count moves and the queue head is never shifted out.
    int i;
    for (i = 0; i < grim_key_char_queue_count; ++i);
    grim_key_char_queue[i] = grim_key_char_queue[i + 1];
#else
    for (int i = 0; i < grim_key_char_queue_count; ++i) {
        grim_key_char_queue[i] = grim_key_char_queue[i + 1];
    }
#endif
    --grim_key_char_queue_count;
    return result;
}
