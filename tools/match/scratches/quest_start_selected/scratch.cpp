#include "crimsonland_gameplay.h"

#define CRIMSONLAND_USE_ORIGINAL_CONFIG_OWNER
#include "crimsonland_config_owner.h"
#define CRIMSONLAND_USE_ORIGINAL_TERRAIN_OWNER
#include "crimsonland_terrain_owner.h"

extern "C" int quest_spawn_timeline;
extern "C" int quest_stage_banner_timer_ms;
extern "C" int quest_spawn_total_creatures;
extern "C" int quest_spawn_last_time_ms;

extern "C" void creature_reset_all(void);
extern "C" void projectile_reset_pools(void);
extern "C" void terrain_generate(quest_meta_t *quest);
extern "C" void quest_build_fallback(
    quest_spawn_entry_t *entries, int *count);

extern "C" void quest_start_selected(int tier, int index)
{
    vec2f_t player_pos;

    creature_reset_all();

    quest_spawn_count = 0;
    quest_spawn_timeline = 0;
    quest_stage_banner_timer_ms = 0;
    fx_queue_rotated = 0;
    fx_queue_count = 0;

    highscore_active_record.hardcore_marker = 0;
    highscore_active_record.survival_elapsed_ms = 0;
    highscore_active_record.score_xp = 0;
    highscore_active_record.quest_stage_minor = 0;
    highscore_active_record.quest_stage_major = 0;
    highscore_active_record.game_mode_id = 0;
    highscore_active_record.most_used_weapon_id = 0;
    highscore_active_record.creature_kill_count = 0;
    highscore_active_record.shots_hit = 0;
    highscore_active_record.shots_fired = 0;
    highscore_active_record.date_checksum = 0;
    highscore_active_record.year_offset = 0;
    highscore_active_record.month = 0;
    highscore_active_record.day = 0;
    highscore_active_record.flags = 0;
    highscore_active_record.random_tag = crt_rand() & 0x0fee050f;

    projectile_reset_pools();

    player_pos.x = (float)terrain_texture_width * 0.5f;
    player_pos.y = (float)terrain_texture_height * 0.5f;
    player_state_table[0].position = player_pos;

    int quest_index = tier * 10 + index - 11;
    quest_meta_t *quest = &quest_selected_meta[quest_index];
    terrain_generate(quest);
    weapon_assign_player(
        0, quest_selected_meta[quest_index].start_weapon_id);
    weapon_assign_player(
        1, quest_selected_meta[quest_index].start_weapon_id);

    console_printf(
        &console_log_queue,
        "Setup tier %d quest %d.\n",
        tier,
        index);

    quest_builder_fn_t builder = quest->builder;
    if (!builder) {
        quest_build_fallback(quest_spawn_table, &quest_spawn_count);
    } else {
        builder(quest_spawn_table, &quest_spawn_count);
    }

    int entry_count = quest_spawn_count;
    quest_spawn_total_creatures = 0;
    quest_spawn_last_time_ms = 0;
    if (entry_count <= 0) {
        return;
    }

    int *count_cursor = &quest_spawn_table[0].count;
    int entries_left = entry_count;
    do {
        int template_id;
        if (config_hardcore) {
            if (count_cursor[0] > 1) {
                template_id = count_cursor[-2];
                if (template_id != 0x3c) {
                    if (template_id == 0x2b) {
                        count_cursor[0] += 2;
                    } else {
                        count_cursor[0] += 8;
                    }
                }
            }
        }

        quest_spawn_total_creatures += count_cursor[0];
        int trigger_time_ms = count_cursor[-1];
        if (quest_spawn_last_time_ms < trigger_time_ms) {
            quest_spawn_last_time_ms = trigger_time_ms;
        }

        count_cursor += sizeof(quest_spawn_entry_t) / sizeof(int);
        --entries_left;
    } while (entries_left != 0);
}
