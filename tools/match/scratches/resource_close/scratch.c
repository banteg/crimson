#include "crimsonland_resource.h"

void resource_close(void)
{
    if (resource_fp != 0) {
        fclose(resource_fp);
    }
}
