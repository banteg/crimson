#include "crimsonland_types.h"

extern "C" effect_color_t reserved_color_4871b8;

extern "C" void reserved_color_global_init(void)
{
    reserved_color_4871b8.r = 1.0f;
    reserved_color_4871b8.g = 0.0f;
    reserved_color_4871b8.b = 0.0f;
    reserved_color_4871b8.a = 1.0f;
}
