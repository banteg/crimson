#include <string.h>

struct game_status_native_t {
    unsigned short quest_unlock_index;
    unsigned short quest_unlock_index_full;
    unsigned int weapon_usage_counts[53];
    unsigned int quest_play_counts[91];
    unsigned int mode_play_survival;
    unsigned int mode_play_rush;
    unsigned int mode_play_typo;
    unsigned int mode_play_other;
    unsigned int game_sequence_id;
    unsigned int reserved_seed_words[4];
};

extern "C" game_status_native_t game_status_blob;
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
