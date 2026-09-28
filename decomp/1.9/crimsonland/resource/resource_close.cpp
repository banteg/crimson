#include "crimsonland_resource.h"

// Resource callers use the C++ free-function identity.
void resource_close(void)
{
    if (resource_fp != 0) {
        fclose(resource_fp);
    }
}
