#include <math.h>

typedef struct IDirectSoundBuffer *LPDIRECTSOUNDBUFFER;

#include "crimsonland_types.h"

extern "C" float vec2_length(const vec2f_t *v)
{
    return (float)sqrt(v->x * v->x + v->y * v->y);
}
