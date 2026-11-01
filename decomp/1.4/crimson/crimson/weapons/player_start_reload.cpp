#include "crimsonland_types.h"
#include "freeware_edition.h"

#if CL_BUILD == 10400
extern "C" player_state_t player_state_table[2];
#define PLAYER(i) player_state_table[i].freeware
#else
extern "C" freeware_player_t player_state_table[2];
#define PLAYER(i) player_state_table[i]
#endif
extern "C" int current_player_index, perk_id_fastloader;
extern "C" int sfx_play_panned(int sample, float volume, float pan);

extern "C" void player_start_reload(void)
{
    sfx_play_panned(16, 0.45f, 0.5f);
#if FREEWARE_EDITION == 10002
    PLAYER(current_player_index).reload = PLAYER(current_player_index).perks[perk_id_fastloader] ? .95f : 1.5f;
#else
    if (PLAYER(current_player_index).weapon == 5)
        PLAYER(current_player_index).reload = 2.0f;
    else if (PLAYER(current_player_index).weapon == 15)
        PLAYER(current_player_index).reload = 1.5f;
    else if (PLAYER(current_player_index).weapon == 10)
        PLAYER(current_player_index).reload = 2.0f;
    else if (PLAYER(current_player_index).weapon == 8)
        PLAYER(current_player_index).reload = 1.7f;
    else if (PLAYER(current_player_index).weapon == 14)
        PLAYER(current_player_index).reload = 3.5f;
    else if (PLAYER(current_player_index).weapon == 13)
        PLAYER(current_player_index).reload = 5.1f;
    else
        PLAYER(current_player_index).reload = 1.2f;
    if (PLAYER(current_player_index).perks[perk_id_fastloader] > 0)
        PLAYER(current_player_index).reload *= 0.7f;
#endif
    PLAYER(current_player_index).reload_duration = PLAYER(current_player_index).reload;
}
