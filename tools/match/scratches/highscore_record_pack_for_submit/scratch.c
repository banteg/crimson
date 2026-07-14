#include <string.h>

#include "crimsonland_highscore.h"

highscore_record_t *highscore_record_pack_for_submit(
    highscore_record_t *src,
    highscore_record_t *dst)
{
    strcpy(dst->player_name, src->player_name);
    dst->survival_elapsed_ms = src->survival_elapsed_ms;
    dst->score_xp = src->score_xp;
    dst->game_mode_id = src->game_mode_id;
    dst->quest_stage_major = src->quest_stage_major;
    dst->quest_stage_minor = src->quest_stage_minor;
    dst->most_used_weapon_id = src->most_used_weapon_id;
    dst->shots_fired = src->shots_fired;
    dst->creature_kill_count = src->creature_kill_count;
    dst->shots_hit = src->shots_hit;
    dst->random_tag = src->random_tag;
    *(unsigned int *)dst->reserved0 = 0;
    return dst;
}
