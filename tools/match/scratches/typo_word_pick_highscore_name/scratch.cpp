#include <string.h>

#include "crimsonland_gameplay.h"

extern "C" void j_highscore_load_table(void);
extern "C" int crt_isalpha(int ch);

extern "C" char typo_word_highscore_cache[100][32];
extern "C" unsigned char typo_word_highscore_cache_ready;
extern "C" int typo_word_highscore_cache_count;

extern "C" char *typo_word_pick_highscore_name(void)
{
    if (!typo_word_highscore_cache_ready) {
        j_highscore_load_table();

        int accepted_count = 0;
        highscore_record_t *record = &highscore_table[0];
        char *cache_cursor = &typo_word_highscore_cache[0][0];
        do {
            bool duplicate = false;
            char *existing = &typo_word_highscore_cache[0][0];
            int cache_index = 0;
            if ((int)cache_cursor
                > (int)&typo_word_highscore_cache[0][0]) {
                while (true) {
                    if (strcmp(record->player_name, existing) == 0) {
                        duplicate = true;
                        break;
                    }
                    ++cache_index;
                    existing += 32;
                    if (cache_index >= accepted_count) {
                        break;
                    }
                }
            }
            if (!duplicate) {
                int length = strlen(record->player_name);
                bool valid = true;
                for (int char_index = 0;
                     char_index < length;
                     ++char_index) {
                    if (!crt_isalpha(record->player_name[char_index])
                        && record->player_name[char_index] != '.') {
                        valid = false;
                        break;
                    }
                }
                if (valid) {
                    char *destination = cache_cursor;
                    cache_cursor += 32;
                    ++accepted_count;
                    strcpy(destination, record->player_name);
                    console_printf(
                        &console_log_queue,
                        "%d. unique: %s\n",
                        accepted_count,
                        record->player_name);
                }
            }
            ++record;
        } while ((int)record < (int)&quest_selected_meta[0]);

        typo_word_highscore_cache_count = accepted_count;
        typo_word_highscore_cache_ready = 1;
        if (accepted_count == 0) {
            crt_sprintf(
                &typo_word_highscore_cache[0][0], "quickbrownfox");
        }
    }

    if (typo_word_highscore_cache_count > 0) {
        return &typo_word_highscore_cache[
            crt_rand() % typo_word_highscore_cache_count][0];
    }
    return &typo_word_highscore_cache[0][0];
}
