#include "crimson_config_defaults_impl.h"

extern "C" void config_init_defaults(void)
{
    ((crimson_cfg_cpp_t *)&config_blob)->set_defaults();
}
