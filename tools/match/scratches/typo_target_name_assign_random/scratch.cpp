#include <string.h>

#include "crimsonland_gameplay.h"

extern "C" char typo_target_name_table[384][64];
extern "C" char *typo_word_pick_highscore_name(void);
extern "C" char *typo_word_pick_fragment(unsigned char prefix);
extern "C" unsigned char typo_target_name_is_unique(char *name, int creature_id);

extern "C" void typo_target_name_assign_random(int creature_id)
{
    int attempts = 0;
    char *name;
    while (true) {
        if ((int)highscore_active_record.score_xp > 120) {
            if (crt_rand() % 100 < 10) {
                name = typo_target_name_table[creature_id];
                strcpy(name, typo_word_pick_highscore_name());
                goto validate_name;
            }
            if ((int)highscore_active_record.score_xp > 120
                && crt_rand() % 100 < 80) {
                name = typo_target_name_table[creature_id];
                crt_sprintf(
                    name,
                    "%s%s%s%s",
                    typo_word_pick_fragment(1),
                    typo_word_pick_fragment(0),
                    typo_word_pick_fragment(0),
                    typo_word_pick_fragment(0));
                goto validate_name;
            }
        }

        if ((int)highscore_active_record.score_xp > 80
            && crt_rand() % 100 < 80) {
            name = typo_target_name_table[creature_id];
            crt_sprintf(
                name,
                "%s%s%s",
                typo_word_pick_fragment(1),
                typo_word_pick_fragment(0),
                typo_word_pick_fragment(0));
        } else if ((int)highscore_active_record.score_xp > 60
                   && crt_rand() % 100 < 40) {
            name = typo_target_name_table[creature_id];
            crt_sprintf(
                name,
                "%s%s%s",
                typo_word_pick_fragment(1),
                typo_word_pick_fragment(0),
                typo_word_pick_fragment(0));
        } else if ((int)highscore_active_record.score_xp > 40
                   && crt_rand() % 100 < 80) {
            name = typo_target_name_table[creature_id];
            crt_sprintf(
                name,
                "%s%s",
                typo_word_pick_fragment(1),
                typo_word_pick_fragment(0));
        } else if ((int)highscore_active_record.score_xp > 20
                   && crt_rand() % 100 < 40) {
            name = typo_target_name_table[creature_id];
            crt_sprintf(
                name,
                "%s%s",
                typo_word_pick_fragment(1),
                typo_word_pick_fragment(0));
        } else {
            name = typo_target_name_table[creature_id];
            crt_sprintf(name, "%s", typo_word_pick_fragment(0));
        }

validate_name:
        if (typo_target_name_is_unique(name, creature_id)) {
            if (strlen(name) <= 15) {
                return;
            }
            if (attempts++ >= 100) {
                return;
            }
        }
    }
}
