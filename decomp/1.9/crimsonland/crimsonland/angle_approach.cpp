#include "crimsonland_gameplay.h"

static __inline float abs_bits(float value)
{
    unsigned int bits = *(unsigned int *)&value;
    bits &= 0x7fffffff;
    return *(float *)&bits;
}

extern "C" float angle_approach(float *angle, float target, float rate)
{
    while (*angle < 0.0f) {
        *angle += 6.2831855f;
    }
    while (*angle > 6.2831855f) {
        *angle -= 6.2831855f;
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
#if CL_BUILD < 10900
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
#else
    if (direct > wrapped) {
        *angle = target < *angle
            ? frame_dt * amount * rate + *angle
            : *angle - frame_dt * amount * rate;
        return amount;
    } else {
        *angle = target > *angle
            ? frame_dt * amount * rate + *angle
            : *angle - frame_dt * amount * rate;
        return amount;
    }
#endif
}
