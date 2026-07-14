#include "crimsonland_resource.h"

void buffer_reader_init(void *data, int size)
{
    buffer_reader_data = data;
    buffer_reader_size = size;
    buffer_reader_offset = 0;
}
