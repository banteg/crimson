#include "crimsonland_highscore.h"

char *highscore_format_date_label(int day, int month_index, int year)
{
    switch (month_index) {
    case 1:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "Jan", year);
        break;
    case 2:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "Feb", year);
        break;
    case 3:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "Mar", year);
        break;
    case 4:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "Apr", year);
        break;
    case 5:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "May", year);
        break;
    case 6:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "Jun", year);
        break;
    case 7:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "Jul", year);
        break;
    case 8:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "Aug", year);
        break;
    case 9:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "Sep", year);
        break;
    case 10:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "Oct", year);
        break;
    case 11:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "Nov", year);
        break;
    case 12:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "Dec", year);
        break;
    default:
        crt_sprintf(highscore_date_label_buffer, "%d. %s %d", day, "???", year);
        break;
    }

    return highscore_date_label_buffer;
}
