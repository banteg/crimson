// Drives the recovered highscore_write_record/highscore_read_record (decomp/1.9) on raw records.
#include <stdio.h>
#include <string.h>

typedef struct { unsigned short wYear, wMonth, wDayOfWeek, wDay, wHour, wMinute, wSecond, wMilliseconds; } SYSTEMTIME;

char *highscore_read_record(char *buffer, FILE *fp);
void highscore_write_record(char *record, FILE *fp);

char default_player_name[32];
SYSTEMTIME local_system_time;
char console_log_queue;
void GetLocalTime(SYSTEMTIME *time) { memset(time, 0, sizeof(*time)); }
int crt_rand(void) { return 0; }
int highscore_iso_week(int year, int month, int day) { return 0; }
void console_printf(void *queue, char *format, ...) {}

// write: decoded records on stdin -> score file on stdout.
// read: score file on stdin -> the decoded records the original accepts on stdout.
int main(int argc, char **argv) {
    char record[0x48];
    if (strcmp(argv[1], "write") == 0) {
        while (fread(record, sizeof(record), 1, stdin) == 1) {
            highscore_write_record(record, stdout);
        }
        return 0;
    }
    while (!feof(stdin)) {
        if (highscore_read_record(record, stdin)) {
            fwrite(record, sizeof(record), 1, stdout);
        }
    }
    return 0;
}
