#include <float.h>

extern "C" int float_near_equal(float a, float b)
{
    float difference = a - b;
    if (-FLT_EPSILON <= difference) {
        if (difference <= FLT_EPSILON) {
            return 1;
        }
    }
    return 0;
}
