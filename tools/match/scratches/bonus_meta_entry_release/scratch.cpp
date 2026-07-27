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

perk_meta_cpp_t::~perk_meta_cpp_t(void)
{
    if (name != 0) {
        crt_free(name);
    }
    if (description != 0) {
        crt_free(description);
    }
}
