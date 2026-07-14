#include <stdio.h>

#include "crimsonland_highscore.h"

char *highscore_read_record(char *buffer, FILE *fp)
{
    int stored_checksum;
    int checksum = 0;
    unsigned int i;
    char *cursor;

    stored_checksum = checksum;
    fread(buffer, sizeof(highscore_record_t), 1, fp);
    if (feof(fp)) {
        return 0;
    }

    fread(&stored_checksum, sizeof(stored_checksum), 1, fp);
    for (i = 0; i < sizeof(highscore_record_t); i++) {
        char decoded = buffer[i];
        decoded += 250 - (i * 5 + 1) * i;
        buffer[i] = decoded;
    }
    cursor = buffer;
    for (i = 0; i < sizeof(highscore_record_t); i++, cursor++) {
        checksum += (i + 3) * *cursor * 7;
    }
    if (stored_checksum != checksum) {
        buffer[31] = 0;
        console_printf(
            &console_log_queue,
            "WARN: checksum failure on score by %s\n",
            buffer);
        return 0;
    }
    return buffer;
}
