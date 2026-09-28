#include "crimsonland_highscore.h"

int highscore_date_checksum(int year, int month, int day)
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
