#include "freeware_score.h"
#include "crimsonland_console.h"
#include <stdio.h>

extern "C" {
extern int config_game_mode;
void freeware_score_table_reset();
#if CL_BUILD > 10002
extern unsigned char freeware_score_corrupt;
void freeware_score_key_init();
unsigned char freeware_score_decode(char *bytes, int size);
char *highscore_build_path();
void crt_free(void *);
#endif
#if CL_BUILD == 10400
extern console_queue_t freeware_console;
#endif
}

extern "C" unsigned char highscore_load_table()
{
#if CL_BUILD == 10002
    freeware_score_table_reset();
    FILE *file;
    if (config_game_mode == 2)
        file = fopen("rush.top", "rb");
    else
        file = fopen("career.top", "rb");
    if (!file)
        return 0;
    fseek(file, 0, SEEK_SET);

    freeware_score_entry record;
    record.value = 0;
    sprintf(record.name, "10tons");
    int count = 0;
    while (!feof(file)) {
        if (!fread(&record, sizeof(record), 1, file))
            break;
        if (count >= 100) {
            for (int i = 0; i < 100; ++i) {
                if (freeware_score_table[i].value < record.value) {
                    freeware_score_table[i] = record;
                    break;
                }
            }
        } else {
            freeware_score_table[count++] = record;
        }
    }
    fclose(file);
#else
    freeware_score_key_init();
    freeware_score_table_reset();
    FILE *file = fopen(highscore_build_path(), "rb");
    if (!file)
        return 0;

    fseek(file, 0, SEEK_END);
    int size = ftell(file) - 4;
    char *bytes = new char[size + 4];
    fseek(file, 0, SEEK_SET);
    fread(bytes, size + 4, 1, file);
    fclose(file);

    freeware_score_corrupt = 0;
    if (!freeware_score_decode(bytes, size)) {
        freeware_score_corrupt = 1;
        for (int i = 0; i < 100; ++i) {
            freeware_score_table[i].value = 0;
            if (i == 0)
                strcpy(freeware_score_table[0].name, "Corrupted high score file.");
            else if (i == 1)
                strcpy(freeware_score_table[1].name, "  (delete *.top files)");
            else if (i == 2)
                strcpy(freeware_score_table[2].name, "(or press D to do it now)");
            else
                strcpy(freeware_score_table[i].name, " ");
        }
        crt_free(bytes);
        return 0;
    }

    freeware_score_entry record;
#if CL_BUILD == 10400
    record.seconds = 0;
#endif
    record.average_fps = 1;
    record.min_fps = 1;
#if CL_BUILD == 10400
    record.version = 1.4f;
#else
    record.version = 1.3f;
#endif
    record.value = 0;
    sprintf(record.name, "10tons");

    int count = size / sizeof(record);
#if CL_BUILD == 10400
    console_printf(&freeware_console, "%d scores found: %d / %d\n", count, size, sizeof(record));
#endif
    int i;
    for (i = 0; i < count; ++i) {
        record = ((freeware_score_entry *)bytes)[i];
        if (record.value > 80000 && (record.version == 1.22f || record.version == 1.24f))
            record.value = 80000;
#if CL_BUILD == 10400
        if (record.version < 1.3f)
#else
        if (record.version != 1.3f)
#endif
            continue;
        if (i >= 100) {
            int lowest = 0;
            for (int j = 0; j < 100; ++j) {
                if (freeware_score_table[j].value < freeware_score_table[lowest].value)
                    lowest = j;
            }
            if (freeware_score_table[lowest].value < record.value)
                freeware_score_table[lowest] = record;
        } else {
            freeware_score_table[i] = record;
        }
    }
    crt_free(bytes);
    if (config_game_mode == 2) {
        for (i = 0; i < 100; ++i)
            freeware_score_table[i].value = freeware_score_table[i].seconds;
    }
#endif
    freeware_sort_score_table();
    return 1;
}
