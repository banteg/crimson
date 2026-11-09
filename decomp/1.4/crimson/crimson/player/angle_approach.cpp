#include "freeware_edition.h"
#include "crimsonland_gameplay.h"
#include <math.h>

extern "C" float freeware_float_max(float, float);
extern "C" float freeware_float_min(float, float);

static __inline float abs_bits(float value)
{
    unsigned int bits = *(unsigned int *)&value;
    bits &= 0x7fffffff;
    return *(float *)&bits;
}

extern "C" float angle_approach(float *angle, float target)
{
    while (*angle < 0.0f) {
        *angle += 6.2831855f;
    }
    while (*angle > 6.2831855f) {
        *angle -= 6.2831855f;
    }

#if FREEWARE_EDITION == 10300
    float direct = fabsf(target - *angle);
    float wrapped = (float)fabs((6.2831855f - freeware_float_max(target, *angle))
                               + freeware_float_min(target, *angle));
    float amount = freeware_float_min(direct, wrapped);
#else
    float direct = abs_bits(target - *angle);
    float high = *angle;
    if (target > high) {
        high = target;
    }
    float low = *angle;
    if (target < low) {
        low = target;
    }
    float wrapped = abs_bits((6.2831855f - high) + low);
    float amount;
    if (direct < wrapped) {
        amount = direct;
    } else {
        amount = wrapped;
    }

#endif

    if (amount > 1.0f) {
        amount = 1.0f;
    }
    if (direct > wrapped) {
        if (target < *angle) {
            *angle += frame_dt * amount * 5.0f;
            return amount;
        } else {
            *angle -= frame_dt * amount * 5.0f;
            return amount;
        }
    } else {
        if (target > *angle) {
            *angle += frame_dt * amount * 5.0f;
            return amount;
        } else {
            *angle -= frame_dt * amount * 5.0f;
            return amount;
        }
    }
}
