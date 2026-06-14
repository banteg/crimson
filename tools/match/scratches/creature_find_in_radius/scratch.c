#include <math.h>
#include "crimsonland_gameplay.h"

int creature_find_in_radius(float *pos, float radius, int start_index)
{
    if (start_index < 0x180) {
        char *creature = (char *)&creature_pool[start_index];
        do {
            if (*(unsigned char *)creature) {
                float dx = *(float *)(creature + 0x14) - pos[0];
                float dy = *(float *)(creature + 0x18) - pos[1];
                if ((float)sqrt(dx * dx + dy * dy) - radius < *(float *)(creature + 0x34) * 0.14285715f + 3.0f) {
                    if (*(float *)(creature + 0x10) > 5.0f) {
                        return start_index;
                    }
                }
            }
            creature += sizeof(creature_t);
            ++start_index;
        } while (creature < (char *)&creature_pool[0x180]);
    }
    return -1;
}
