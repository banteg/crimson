#include <string.h>

#include "crimsonland_gameplay.h"

extern "C" void highscore_load_table_thunk(void);
extern "C" int crt_isalpha(int ch);

extern "C" char typo_word_highscore_cache[20][32];
extern "C" unsigned char typo_word_highscore_cache_ready;
extern "C" int typo_word_highscore_cache_count;

extern "C" char *typo_word_pick_highscore_name(void)
{
    if (!typo_word_highscore_cache_ready) {
        highscore_load_table_thunk();

        int accepted_count = 0;
        for (int record_index = 0; record_index < 100; ++record_index) {
            bool duplicate = false;
            for (int cache_index = 0; cache_index < accepted_count; ++cache_index) {
                if (strcmp(highscore_table[record_index].player_name,
                           typo_word_highscore_cache[cache_index]) == 0) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                int length = strlen(highscore_table[record_index].player_name);
                bool valid = true;
                for (int char_index = 0; char_index < length; ++char_index) {
                    if (!crt_isalpha(highscore_table[record_index].player_name[char_index])
                        && highscore_table[record_index].player_name[char_index] != '.') {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    strcpy(typo_word_highscore_cache[accepted_count++],
                           highscore_table[record_index].player_name);
                    console_printf(
                        &console_log_queue,
                        "%d. unique: %s\n",
                        accepted_count,
                        highscore_table[record_index].player_name);
                }
            }
        }

        typo_word_highscore_cache_count = accepted_count;
        typo_word_highscore_cache_ready = 1;
        if (accepted_count == 0) {
            crt_sprintf(
                &typo_word_highscore_cache[0][0], "quickbrownfox");
        }
    }

    if (typo_word_highscore_cache_count > 0) {
        return typo_word_highscore_cache[
            crt_rand() % typo_word_highscore_cache_count];
    }
    return typo_word_highscore_cache[0];
}
