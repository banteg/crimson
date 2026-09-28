#include "crimsonland_gameplay.h"

extern "C" void effect_uv_tables_init(void)
{
    int x;
    int y;
    float *cell;
    float *row;

    for (x = 0; x < 16; ++x) {
        effect_uv_strip16[x].u = (float)x * (1.0f / 16.0f);
        effect_uv_strip16[x].v = 0.0f;
    }

    y = 0;
    row = &effect_uv2[0].v;
    do {
        x = 0;
        cell = row;
        row += 4;
        do {
            cell[-1] = (float)x * (1.0f / 2.0f);
            cell[0] = (float)y * (1.0f / 2.0f);
            cell += 2;
            ++x;
        } while (x < 2);
        ++y;
    } while (y < 2);

    y = 0;
    row = &effect_uv4[0].v;
    do {
        x = 0;
        cell = row;
        row += 8;
        do {
            cell[-1] = (float)x * (1.0f / 4.0f);
            cell[0] = (float)y * (1.0f / 4.0f);
            cell += 2;
            ++x;
        } while (x < 4);
        ++y;
    } while (y < 4);

    y = 0;
    row = &effect_uv8[0].v;
    do {
        x = 0;
        cell = row;
        row += 16;
        do {
            cell[-1] = (float)x * (1.0f / 8.0f);
            cell[0] = (float)y * (1.0f / 8.0f);
            cell += 2;
            ++x;
        } while (x < 8);
        ++y;
    } while (y < 8);

    y = 0;
    row = &effect_uv16[0].v;
    do {
        x = 0;
        cell = row;
        row += 32;
        do {
            cell[-1] = (float)x * (1.0f / 16.0f);
            cell[0] = (float)y * (1.0f / 16.0f);
            cell += 2;
            ++x;
        } while (x < 16);
        ++y;
    } while (y < 16);
}
