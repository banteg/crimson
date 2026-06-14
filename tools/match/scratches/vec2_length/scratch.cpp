#include <math.h>

extern "C" float vec2_length(float *v)
{
    return (float)sqrt(v[0] * v[0] + v[1] * v[1]);
}
