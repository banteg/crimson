#include "crimsonland_gameplay.h"

void highscore_record_init(void)
{
    int most_used_weapon_id = 1;
    int weapon_id;

    for (weapon_id = 1; weapon_id < 64; ++weapon_id) {
        if ((int)weapon_usage_time[weapon_id]
            > (int)weapon_usage_time[most_used_weapon_id]) {
            most_used_weapon_id = weapon_id;
        }
    }

    highscore_active_record.most_used_weapon_id = (unsigned char)most_used_weapon_id;
    if ((int)highscore_active_record.shots_hit
        > (int)highscore_active_record.shots_fired) {
        highscore_active_record.shots_hit = highscore_active_record.shots_fired;
    }
    highscore_active_record.game_mode_id = (unsigned char)config_game_mode;
    highscore_active_record.quest_stage_major = (unsigned char)quest_stage_major;
    highscore_active_record.quest_stage_minor = (unsigned char)quest_stage_minor;
    highscore_active_record.flags = 0;
    highscore_active_record.random_tag = crt_rand() % 0x10000000 + 0x310;
    highscore_active_record.hardcore_marker = config_hardcore ? 0x75 : 0;
}
