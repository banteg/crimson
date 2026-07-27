#include "crimsonland_resource.h"

// The native callers use the C++ free-function identity.
unsigned short buffer_reader_read_u16(void)
{
    unsigned short value = *(unsigned short *)(buffer_reader_data + buffer_reader_offset);
    buffer_reader_offset += 2;
    return value;
}
