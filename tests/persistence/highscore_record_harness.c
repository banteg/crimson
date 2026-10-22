// Drives the recovered highscore_write_record (decomp/1.9) on raw records.
#include <stdio.h>
#include <string.h>

typedef struct { unsigned short wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds; } SYSTEMTIME;

void highscore_write_record(char *record, FILE *fp);

char default_player_name[32];
SYSTEMTIME local_system_time;
char console_log_queue;
void GetLocalTime(SYSTEMTIME *time) { memset(time, 0, sizeof(*time)); }
int crt_rand(void) { return 0; }
int highscore_iso_week(int year, int month, int day) { return 0; }
void console_printf(void *queue, char *format, ...) {}

// Decoded records on stdin -> score file on stdout.
int main(void) {
    char record[0x48];
    while (fread(record, sizeof(record), 1, stdin) == 1) {
        highscore_write_record(record, stdout);
    }
    return 0;
}
