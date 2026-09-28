#include "crimsonland_gameplay.h"

int highscore_compare_rush_field32_desc(const void *lhs, const void *rhs)
{
    int lhs_time = (int)((const highscore_record_t *)lhs)->survival_elapsed_ms;
    int rhs_time = (int)((const highscore_record_t *)rhs)->survival_elapsed_ms;

    if (lhs_time > rhs_time) {
        return -1;
    }
    if (lhs_time < rhs_time) {
        return 1;
    }
    return 0;
}
