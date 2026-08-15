#include "grim2d_cpp.h"

extern grim_config_value_t grim_config_values[128];
extern grim_config_value_t grim_config_default;

grim_config_value_t IGrim2D_cpp::grim_get_config_var(int id)
{
    if (id >= 0 && id < 128)
        return grim_config_values[id];
    return grim_config_default;
}
