#include "crimsonland_resource.h"

// The native callers use the C++ free-function identity.
void buffer_reader_seek(int offset)
{
    buffer_reader_offset = offset;
}
