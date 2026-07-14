#include "crimsonland_gameplay.h"

int highscore_compare_quest_field32_asc_nonzero_first(
    const void *lhs,
    const void *rhs)
{
    int lhs_time = (int)((const highscore_record_t *)lhs)->survival_elapsed_ms;
    int rhs_time;

    if (lhs_time == 0) {
        return 1;
    }

    rhs_time = (int)((const highscore_record_t *)rhs)->survival_elapsed_ms;
    if (rhs_time == 0) {
        return -1;
    }
    if (lhs_time > rhs_time) {
        return 1;
    }
    if (lhs_time < rhs_time) {
        return -1;
    }
    return 0;
}
