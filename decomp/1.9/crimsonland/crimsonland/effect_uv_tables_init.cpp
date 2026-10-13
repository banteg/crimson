#include "crimsonland_gameplay.h"

extern "C" void effect_uv_tables_init(void)
{
    int index;
    int x;
    int y;

    for (x = 0; x < 16; ++x) {
        effect_uv_strip16[x].u = (float)x * (1.0f / 16.0f);
        effect_uv_strip16[x].v = 0.0f;
    }

    index = 0;
    for (y = 0; y < 2; ++y) {
        for (x = 0; x < 2; ++x) {
            effect_uv2[index].u = (float)x * (1.0f / 2.0f);
            effect_uv2[index].v = (float)y * (1.0f / 2.0f);
            ++index;
        }
    }

    index = 0;
    for (y = 0; y < 4; ++y) {
        for (x = 0; x < 4; ++x) {
            effect_uv4[index].u = (float)x * (1.0f / 4.0f);
            effect_uv4[index].v = (float)y * (1.0f / 4.0f);
            ++index;
        }
    }

    index = 0;
    for (y = 0; y < 8; ++y) {
        for (x = 0; x < 8; ++x) {
            effect_uv8[index].u = (float)x * (1.0f / 8.0f);
            effect_uv8[index].v = (float)y * (1.0f / 8.0f);
            ++index;
        }
    }

    index = 0;
    for (y = 0; y < 16; ++y) {
        for (x = 0; x < 16; ++x) {
            effect_uv16[index].u = (float)x * (1.0f / 16.0f);
            effect_uv16[index].v = (float)y * (1.0f / 16.0f);
            ++index;
        }
    }
}
