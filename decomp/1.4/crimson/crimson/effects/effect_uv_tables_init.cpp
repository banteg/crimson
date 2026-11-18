#include "crimsonland_types.h"

extern "C" vec2f_t freeware_atlas_uv[64];

extern "C" void effect_uv_tables_init(void)
{
    int index = 0;
    for (int y = 0; y < 512; y += 64) {
        const float v = y * (1.0f / 512.0f);
        for (int x = 0; x < 512; x += 64) {
            freeware_atlas_uv[index].x = x * (1.0f / 512.0f);
            freeware_atlas_uv[index].y = v;
            ++index;
        }
    }
}
