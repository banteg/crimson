#include <string.h>

#include "crimsonland_gameplay.h"

extern "C" game_status_t game_status_blob;
extern "C" int crt_rand(void);

extern "C" void game_status_global_init(void)
{
    game_status_blob.mode_play_typo = 0;
    game_status_blob.mode_play_survival = 0;
    game_status_blob.mode_play_rush = 0;
    game_status_blob.mode_play_other = 0;

    memset(&game_status_blob.quest_play_counts[51], 0, 50);
    memset(&game_status_blob.quest_play_counts[11], 0, 50);
    memset(game_status_blob.weapon_usage_counts, 0, 0x100);

    game_status_blob.quest_unlock_index = 0;
    game_status_blob.quest_unlock_index_full = 0;
    game_status_blob.game_sequence_id = 0;

    game_status_blob.reserved_seed_words[0] = crt_rand() % 345354345;
    game_status_blob.reserved_seed_words[1] = crt_rand() % 345354345;
    game_status_blob.reserved_seed_words[2] = crt_rand() % 345354345;
    game_status_blob.reserved_seed_words[3] = crt_rand() % 345354345;
}
