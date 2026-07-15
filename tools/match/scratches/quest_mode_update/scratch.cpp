#include "crimsonland_gameplay.h"
#include "grim2d_cpp.h"

extern "C" unsigned char console_open_flag;
extern "C" unsigned char ui_transition_direction;
extern "C" int frame_dt_ms;
extern "C" int quest_spawn_timeline;
extern "C" int quest_stage_banner_timer_ms;
extern "C" game_state_id_t game_state_pending;
extern "C" game_status_t game_status_blob;
extern "C" int highscore_score_xp;
extern "C" IGrim2D_cpp *grim_interface_ptr;

extern "C" int music_track_extra_0;
extern "C" int music_track_crimsonquest_id;
extern "C" int sfx_questhit;
extern "C" sfx_volume_table_t sfx_volume_table;

extern "C" unsigned char creatures_none_active(void);
extern "C" unsigned char quest_spawn_table_empty(void);
extern "C" void quest_spawn_timeline_update(void);
extern "C" void sfx_mute_all(int sfx_id);
extern "C" void sfx_play_exclusive(int sfx_id);
extern "C" void game_save_status(void);
extern "C" int console_input_poll(void);

extern "C" void quest_mode_update(void)
{
    if (!console_open_flag && render_pass_mode) {
        if (!creatures_none_active() || !quest_spawn_table_empty()) {
            quest_spawn_timeline += frame_dt_ms;
        }
        quest_stage_banner_timer_ms += frame_dt_ms;
    }
    quest_spawn_timeline_update();

    if (demo_mode_active
        || !creatures_none_active()
        || !quest_spawn_table_empty()) {
        return;
    }

    int timer = quest_transition_timer_ms;
    bonus_reflex_boost_timer = 0.0f;
    if (timer < 0) {
        sfx_mute_all(music_track_extra_0);
        int quest_index = quest_stage_major * 10 + quest_stage_minor;
        int play_count = game_status_blob.quest_play_counts[40 + quest_index];
        ++play_count;
        game_status_blob.quest_play_counts[40 + quest_index] = play_count;
        quest_transition_timer_ms = frame_dt_ms;
        return;
    }

    if (timer > 800 && timer <= 850) {
        sfx_play(sfx_questhit, 1.0f);
        int next_timer = 851;
        next_timer += frame_dt_ms;
        quest_transition_timer_ms = next_timer;
        return;
    }

    if (timer > 2000 && timer <= 2050) {
        quest_transition_timer_ms = 2051;
        sfx_play_exclusive(music_track_crimsonquest_id);
        int next_timer = frame_dt_ms + quest_transition_timer_ms;
        sfx_volume_table[music_track_crimsonquest_id] = 0.0f;
        quest_transition_timer_ms = next_timer;
        return;
    }

    if (timer > 2500) {
        int next_unlock =
            quest_stage_major * 10 + quest_stage_minor - 10;
        if (next_unlock > quest_unlock_index) {
            quest_unlock_index = next_unlock;
        }
        if (config_hardcore
            && next_unlock > quest_unlock_index_full) {
            quest_unlock_index_full = next_unlock;
        }
        game_save_status();
        game_state_pending = GAME_STATE_QUEST_RESULTS;
        ui_transition_direction = 0;
        grim_interface_ptr->grim_flush_input();
        console_input_poll();
        highscore_score_xp = 0;
    }

    quest_transition_timer_ms += frame_dt_ms;
}
