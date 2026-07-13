#include <string.h>

#include "crimsonland_gameplay.h"

int gameplay_run_state_init(void)
{
    memset(&highscore_active_record, 0, sizeof(highscore_active_record));
    strcpy(highscore_active_record.player_name, default_player_name);
    highscore_active_record.flags = 0;
    highscore_active_record.sentinel_pipe = 124;
    highscore_active_record.sentinel_ff = -1;
    *(int *)highscore_active_record.reserved0 = crt_rand() & 0x0fee050f;

    bonus_energizer_timer = 0.0f;
    survival_spawn_stage = 0;
    gameplay_run_reserved_zero = 0;
    quest_fail_retry_count = 0;
    demo_mode_active = 0;
    main_menu_full_version_layout_latch = 0;
    quest_unlock_index = 0;
    creature_active_count = 0;
    time_played_ms = 0;
    quest_transition_timer_ms = -1;
    quest_stage_major = 1;
    quest_stage_minor = 1;
    return 1;
}
