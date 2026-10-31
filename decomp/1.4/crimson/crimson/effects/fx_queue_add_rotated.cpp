// crimson.exe 1.4.0, 0x40e730.
#include "freeware_fx_queues.h"
extern "C" int crt_rand();
#define COUNT FX_STORE(freeware_corpse_count, corpse_count)
#define COLORS FX_STORE(freeware_corpse_colors, corpse_colors)
#define ANGLES FX_STORE(freeware_corpse_angles, corpse_angles)
#define SIZES FX_STORE(freeware_corpse_sizes, corpse_sizes)
#define SPECIES FX_STORE(freeware_corpse_species, corpse_species)
#define POSITIONS FX_STORE(freeware_corpse_positions, corpse_positions)
extern "C" void fx_queue_add_rotated(const vec2f_t *pos, const effect_color_t *color, float angle, float size,
                                     int species) {
    if (COUNT == 63) {
        int i = crt_rand() % 64;
        COLORS[i] = *color;
        ANGLES[i] = angle;
        SIZES[i] = size;
        SPECIES[i] = species;
        POSITIONS[i] = *pos;
    } else {
        COLORS[COUNT] = *color;
        ANGLES[COUNT] = angle;
        SIZES[COUNT] = size;
        SPECIES[COUNT] = species;
        POSITIONS[COUNT++] = *pos;
    }
    if (COUNT >= 64)
        COUNT = 63;
}
