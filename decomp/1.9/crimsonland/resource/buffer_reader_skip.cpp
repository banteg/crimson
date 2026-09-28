#include "crimsonland_resource.h"

// The native callers use the C++ free-function identity.
void buffer_reader_skip(int count)
{
    buffer_reader_offset += count;
}
