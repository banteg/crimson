#include "crimsonland_metadata.h"

perk_meta_cpp_t::perk_meta_cpp_t(void)
{
#if CL_BUILD < 10300
    name = 0;
    description = 0;
#elif CL_BUILD < 10400
    name = 0;
    description = 0;
    available = 1;
#else
    name = 0;
    description = 0;
    available = 1;
    available_default = 0;
#endif
}
