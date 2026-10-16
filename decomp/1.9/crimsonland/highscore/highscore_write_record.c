#include <windows.h>

#include "crimsonland_highscore_record.h"

extern "C" SYSTEMTIME local_system_time;

#if CL_BUILD == 10908
/*
 * Translation-unit context for 1.9.8. Its C2 (9044) reuses what it learned
 * compiling earlier functions of the same unit: highscore_iso_week precedes
 * this function there (see highscore_iso_week.c) and reads no memory, so the
 * reset's random tag store, overwritten by the record copy, is dropped.
 * 1.9.93's C2 (8966) ignores this, so the canonical object keeps one function
 * per file.
 */
extern "C" int highscore_iso_week(int year, int month, int day)
{
    int a = (14 - month) / 12;
    int y = year + 4800 - a;
    int m = month + 12 * a - 3;
    int julian_day =
        day + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 +
        y / 400 - 32045;
    int d4 =
        (julian_day + 31741 - julian_day % 7) % 146097 % 36524 % 1461;
    int leap = d4 / 1460;
    int d1 = ((d4 - leap) % 365) + leap;

    return d1 / 7 + 1;
}
#endif

void highscore_write_record(highscore_record_t *record, FILE *fp)
{
    int checksum = 0;
    highscore_record_cpp_t encoded;
    unsigned int i;
    char *cursor;

    GetLocalTime(&local_system_time);

    encoded.reset_light();

    if (record->day == 0) {
        record->day = (unsigned char)local_system_time.wDay;
        record->month = (unsigned char)local_system_time.wMonth;
        record->year_offset =
            (unsigned char)(local_system_time.wYear - 2000);
        record->date_week = highscore_iso_week(
            local_system_time.wYear,
            local_system_time.wMonth,
            local_system_time.wDay);
    }

    memcpy(&encoded, record, sizeof(encoded));
    cursor = (char *)&encoded;
    for (i = 0; i < sizeof(encoded); i++, cursor++) {
        checksum += (i + 3) * *cursor * 7;
    }
    for (i = 0; i < sizeof(encoded); i++) {
        ((char *)&encoded)[i] += (i * 5 + 1) * i + 6;
    }

    fwrite(&encoded, sizeof(encoded), 1, fp);
    fwrite(&checksum, sizeof(checksum), 1, fp);
}
