#include <float.h>
#include <math.h>

struct vec2_t {
    float x;
    float y;

    float length_sq() const
    {
        return x * x + y * y;
    }

    vec2_t operator*(float scale) const
    {
        vec2_t result = {x * scale, y * scale};
        return result;
    }
};

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

extern "C" vec2_t *__stdcall vec2_normalize_safe(vec2_t *dst, const vec2_t *src)
{
    float magnitude_sq = src->length_sq();
    if (float_near_equal(magnitude_sq, 1.0f)) {
        if (dst != src) {
            *dst = *src;
        }
    } else if (magnitude_sq > FLT_MIN) {
        float inv_magnitude = 1.0f / (float)sqrt(magnitude_sq);
        *dst = *src * inv_magnitude;
    } else {
        dst->x = 0.0f;
        dst->y = 0.0f;
    }
    return dst;
}
