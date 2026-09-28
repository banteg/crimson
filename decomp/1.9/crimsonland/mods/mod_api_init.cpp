#include <new.h>

#include "crimsonland_mod_api.h"

extern mod_api_cpp_t mod_api_context;

extern "C" void mod_api_init(void)
{
    __assume(&mod_api_context != 0);
    new (&mod_api_context) mod_api_cpp_t;
}
