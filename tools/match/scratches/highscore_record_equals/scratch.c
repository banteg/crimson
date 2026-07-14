#include <string.h>

#include "crimsonland_highscore.h"

char highscore_record_equals(
    highscore_record_t *left,
    highscore_record_t *right)
{
    if (left->score_xp != right->score_xp) {
        return 0;
    }
    if (left->survival_elapsed_ms != right->survival_elapsed_ms) {
        return 0;
    }
    if (left->game_mode_id != right->game_mode_id) {
        return 0;
    }
    if (left->creature_kill_count != right->creature_kill_count) {
        return 0;
    }
    if (left->shots_hit != right->shots_hit) {
        return 0;
    }
    if (left->shots_fired != right->shots_fired) {
        return 0;
    }
    return strcmp(left->player_name, right->player_name) == 0;
}
