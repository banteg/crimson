#include "crimsonland_gameplay.h"

int highscore_compare_survival_score_desc(const void *lhs, const void *rhs)
{
    int lhs_score = (int)((const highscore_record_t *)lhs)->score_xp;
    int rhs_score = (int)((const highscore_record_t *)rhs)->score_xp;

    if (lhs_score > rhs_score) {
        return -1;
    }
    if (lhs_score < rhs_score) {
        return 1;
    }
    return 0;
}
