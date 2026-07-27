typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;

#include "crimsonland_types.h"

extern "C" int vec2_add_inplace(
    int entity_index,
    vec2f_t *pos,
    const vec2f_t *delta)
{
    pos->x = pos->x + delta->x;
    pos->y = delta->y + pos->y;
    return 0;
}
