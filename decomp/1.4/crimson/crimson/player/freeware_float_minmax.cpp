// The 1.0.2 and 1.3.0 heading helpers call these scalar comparisons.
#include "freeware_edition.h"
#if FREEWARE_EDITION < 10400
extern "C" float freeware_float_min(float a, float b) {
    if (a < b)
        return a;
    return b;
}

extern "C" float freeware_float_max(float a, float b) {
    if (a > b)
        return a;
    return b;
}
#endif
