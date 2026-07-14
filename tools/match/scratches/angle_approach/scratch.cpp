#include "crimsonland_gameplay.h"

static __inline float abs_bits(float value)
{
    unsigned int bits = *(unsigned int *)&value;
    bits &= 0x7fffffff;
    return *(float *)&bits;
}

extern "C" float angle_approach(float *angle, float target, float rate)
{
    float current = *angle;
    while (current < 0.0f) {
        current = *angle + 6.2831855f;
        *angle = current;
    }
    current = *angle;
    while (current > 6.2831855f) {
        current = *angle - 6.2831855f;
        *angle = current;
    }

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

    if (amount > 1.0f) {
        amount = 1.0f;
    }
    float step;
    if (direct > wrapped) {
        step = frame_dt * amount * rate;
        if (target < *angle) {
            *angle = step + *angle;
            return amount;
        }
    } else {
        step = frame_dt * amount * rate;
        if (target > *angle) {
            *angle = step + *angle;
            return amount;
        }
    }
    *angle = *angle - step;
    return amount;
}
