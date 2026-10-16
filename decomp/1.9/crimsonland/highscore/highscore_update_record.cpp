#include "crimsonland_highscore_record.h"

extern "C" char *highscore_read_record(char *buffer, FILE *fp);

unsigned char highscore_update_record(
    char *path,
    highscore_record_t *record)
{
    highscore_record_cpp_t stored;
    FILE *fp;

    stored.reset_light();

    fp = fopen(path, "r+b");
    if (fp == 0) {
        return 0;
    }

    while (!feof(fp)) {
        if (highscore_read_record((char *)&stored, fp) != 0 &&
            highscore_record_equals(record, &stored)) {
            if ((stored.flags & 2) != 0) {
                fclose(fp);
                return 1;
            }
            if (stored.flags == 0) {
                record->flags = 2;
            }
            fseek(fp, -(long)(sizeof(stored) + sizeof(int)), SEEK_CUR);
            highscore_write_record(record, fp);
            fflush(fp);
            fclose(fp);
            return 1;
        }
    }

    fflush(fp);
    fclose(fp);
    return 0;
}
