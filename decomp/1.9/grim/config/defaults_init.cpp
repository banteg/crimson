#include "crimson_config_defaults_impl.h"

extern crimson_cfg_t grim_config_blob;

extern "C" void grim_config_defaults_init(void)
{
    ((crimson_cfg_cpp_t *)&grim_config_blob)->set_defaults();
}
