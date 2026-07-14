#include "crimsonland_resource.h"

void buffer_reader_skip(int count)
{
    buffer_reader_offset += count;
}
