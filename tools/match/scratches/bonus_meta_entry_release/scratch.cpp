#include "crimsonland_metadata.h"

bonus_meta_cpp_t::~bonus_meta_cpp_t(void)
{
    if (label != 0) {
        crt_free(label);
    }
    if (description != 0) {
        crt_free(description);
    }
}
