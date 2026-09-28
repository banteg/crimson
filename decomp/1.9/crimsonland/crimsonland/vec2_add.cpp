typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;

#include "crimsonland_types.h"

extern "C" int vec2_add(
    vec2f_t *dst,
    const vec2f_t *delta,
    float)
{
    dst->x = dst->x + delta->x;
    dst->y = delta->y + dst->y;
    return 0;
}
