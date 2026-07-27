#include "crimsonland_resource.h"

// The native callers use the C++ free-function identity.
void buffer_reader_init(void *data, int size)
{
    buffer_reader_data = (char *)data;
    buffer_reader_size = size;
    buffer_reader_offset = 0;
}
