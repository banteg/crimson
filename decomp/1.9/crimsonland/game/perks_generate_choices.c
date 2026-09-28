#include <string.h>

#include "crimsonland_gameplay.h"

extern int perk_choice_ids[7];
extern quest_meta_t *quest_monster_vision_meta;

extern int perk_id_sharpshooter;
extern int perk_id_fastshot;
extern int perk_id_long_distance_runner;
extern int perk_id_jinxed;
extern int perk_id_grim_deal;
extern int perk_id_radioactive;
extern int perk_id_evil_eyes;
extern int perk_id_anxious_loader;
extern int perk_id_infernal_contract;
extern int perk_id_regeneration;
extern int perk_id_greater_regeneration;
extern int perk_id_breathing_room;
extern int perk_id_pyromaniac;
extern int perk_id_fatal_lottery;
extern int perk_id_monster_vision;
extern int perk_id_death_clock;
extern int perk_id_bandage;
extern int perk_id_count;

extern int perk_select_random(void);

void perks_generate_choices(void)
{
    int choice_index;
    int i;
    int *choice_cursor;
    int ammunition_within;
    int jinxed;
    int attempts;
    int perk_id;
    int death_clock_count;
    memset(perk_choice_ids, 0, sizeof(perk_choice_ids));
    choice_index = 0;

    do {
        if (choice_index == 0
            && quest_stage_major == quest_monster_vision_meta->tier
            && quest_stage_minor == quest_monster_vision_meta->index
            && perk_count_get(perk_id_monster_vision) == 0) {
            choice_index = 1;
            perk_choice_ids[0] = perk_id_monster_vision;
        }

        attempts = 0;
    retry:
        ++attempts;
        perk_id = perk_select_random();
        perk_choice_ids[choice_index] = perk_id;

        if (perk_id == perk_id_pyromaniac
            && player_state_table[0].weapon_id != WEAPON_ID_FLAMETHROWER) {
            goto retry;
        }

        death_clock_count = perk_count_get(perk_id_death_clock);
        ammunition_within = perk_id_ammunition_within;
        jinxed = perk_id_jinxed;
        if (death_clock_count != 0) {
            perk_id = perk_choice_ids[choice_index];
            if (perk_id == jinxed
                || perk_id == perk_id_breathing_room
                || perk_id == perk_id_grim_deal
                || perk_id == perk_id_highlander
                || perk_id == perk_id_fatal_lottery
                || perk_id == perk_id_count
                || perk_id == ammunition_within
                || perk_id == perk_id_infernal_contract
                || perk_id == perk_id_regeneration
                || perk_id == perk_id_greater_regeneration
                || perk_id == perk_id_thick_skinned
                || perk_id == perk_id_bandage) {
                goto retry;
            }
        }

        perk_id = perk_choice_ids[choice_index];
        if ((perk_id == jinxed
                || perk_id == ammunition_within
                || perk_id == perk_id_anxious_loader
                || perk_id == perk_id_monster_vision)
            && (crt_rand() & 3) == 1) {
            goto retry;
        }

        if (attempts > 10000
            && (perk_meta_table[perk_choice_ids[choice_index]].flags & 4) != 0) {
            goto accepted;
        }

        i = 0;
        choice_cursor = perk_choice_ids;
        while (1) {
            if (i >= choice_index) {
                break;
            }
            if (*choice_cursor == perk_choice_ids[choice_index]) {
                goto retry;
            }
            ++i;
            ++choice_cursor;
        }

        perk_id = perk_choice_ids[choice_index];
        if ((perk_meta_table[perk_id].flags & 4) != 0
            || player_state_table[0].perk_counts[perk_id] <= 0
            || attempts >= 30000) {
            goto accepted;
        }
        goto retry;

    accepted:
        if (attempts >= 25000) {
            console_printf(
                &console_log_queue,
                "Perk Randomizer failed to generate random unpicked perks.\n"
            );
        }
        ++choice_index;
    } while (choice_index < 7);

    if (config_game_mode == GAME_MODE_TUTORIAL) {
        perk_choice_ids[0] = perk_id_sharpshooter;
        perk_choice_ids[1] = perk_id_long_distance_runner;
        perk_choice_ids[2] = perk_id_evil_eyes;
        perk_choice_ids[3] = perk_id_radioactive;
        perk_choice_ids[4] = perk_id_fastshot;
        perk_choice_ids[5] = perk_id_fastshot;
        perk_choice_ids[6] = perk_id_fastshot;
    }
}
