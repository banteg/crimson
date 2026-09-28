#include "grim2d_cpp.h"

extern unsigned char *grim_key_char_buffer;
extern int *grim_key_char_buffer_count;
extern int grim_key_char_buffer_size;

void IGrim2D_cpp::grim_set_key_char_buffer(
    unsigned char *buffer, int *count, int size)
{
    grim_key_char_buffer = buffer;
    grim_key_char_buffer_count = count;
    grim_key_char_buffer_size = size;
}
