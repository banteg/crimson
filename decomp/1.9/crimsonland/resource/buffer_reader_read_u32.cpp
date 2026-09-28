#include "crimsonland_resource.h"

// The native callers use the C++ free-function identity.
unsigned int buffer_reader_read_u32(void)
{
    unsigned int value = *(unsigned int *)(buffer_reader_data + buffer_reader_offset);
    buffer_reader_offset += 4;
    return value;
}
