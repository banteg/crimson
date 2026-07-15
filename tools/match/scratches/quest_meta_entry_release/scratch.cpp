#include "crimsonland_metadata.h"

quest_meta_cpp_t::~quest_meta_cpp_t(void)
{
    if (name != 0) {
        crt_free(name);
    }
}
