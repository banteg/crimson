#include <string.h>

#include "crimsonland_gameplay.h"

extern crimson_cfg_t grim_config_blob;

#define CRIMSON_CONFIG_DEFAULTS_FUNCTION grim_config_defaults_init
#define CRIMSON_CONFIG_DEFAULTS_BLOB grim_config_blob
#include "crimson_config_defaults_impl.h"

extern "C" void grim_config_defaults_init_thunk(void)
{
    grim_config_defaults_init();
}
