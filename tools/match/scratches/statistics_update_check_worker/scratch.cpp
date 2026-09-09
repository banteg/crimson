#include <process.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>

#include "crimsonland_console.h"

extern int online_sync_status;
extern char *update_notice_url;
extern unsigned char update_notice_pending;
extern char s_empty_string;
extern "C" void crt_endthread(void);

extern "C" void statistics_update_check_worker(void *)
{
    online_sync_status = 1;
    console_printf(&console_log_queue, "beginthread () (version check)\n");
    console_log_queue.flush_log("console.log");

    char *headers = "Content-Disposition: inline; filename=\"test\"\r\n"
                    "Content-type: application/octet-stream";
    bool parsed = false;
    HINTERNET internet = 0;
    HINTERNET connection = 0;
    HINTERNET request = 0;
    DWORD bytes_read = 0;
    BOOL request_ok;
    BOOL read_ok;
    DWORD received;
    int version[3];
    const char *accept_types[] = {
        "image/gif",
        "image/x-xbitmap",
        "image/jpeg",
        "image/pjpeg",
        "application/vnd.ms-powerpoint",
        "application/vnd.ms-excel",
        "application/msword",
        "application/x-comet",
        "application/octet-stream",
        "*/*",
        0,
    };
    DWORD headers_length = strlen(headers);
    DWORD response_error;

    char *data = new char[0x8000];
    memset(data, 0, 0x8000);

    internet = InternetOpenA("Crimsonland", 0, 0, 0, 0);
    if (!internet) {
        console_printf(&console_log_queue, "Version Check: InternetOpen failed.\n");
        goto cleanup;
    }

    {
        char server_address[64];
        memset(server_address, 0, sizeof(server_address));
        strcpy(server_address, "www.crimsonland.com");
        connection = InternetConnectA(internet, server_address, 80, "guest",
            &s_empty_string, 3, 0x44000000, 0x1289);
    }

    {
        char request_path[64];
        memset(request_path, 0, sizeof(request_path));
        request_path[0] = '/';
        request_path[1] = 'r';
        request_path[2] = 'a';
        request_path[3] = '_';
        request_path[4] = 'v';
        request_path[5] = 'e';
        request_path[6] = 'r';
        request_path[7] = 's';
        request_path[8] = 'i';
        request_path[9] = 'o';
        request_path[10] = 'n';
        request_path[11] = '.';
        request_path[12] = 'p';
        request_path[13] = 'h';
        request_path[14] = 'p';
        if (connection) {

            request = HttpOpenRequestA(connection, "POST", request_path, "HTTP/1.1",
                "none", accept_types, 0x04000000, 0x1289);
            if (request) {

                request_ok
                    = HttpSendRequestA(request, headers, headers_length, data, 0);
                console_printf(&console_log_queue, "Connecting server...\n");
                if (!request_ok) {
                    console_printf(
                        &console_log_queue, "Version Check: HttpSendRequest failed.\n");
                    goto cleanup;
                }

                console_printf(&console_log_queue, "Receiving data...\n");
                memset(data, 0, 0x8000);

                read_ok = InternetReadFile(request, data, 0x400, &bytes_read);
                received = bytes_read;
                for (;;) {
                    if (!read_ok) {
                        break;
                    }
                    if ((int)(received + 0x400) > 0x8000) {
                        goto receive_overflow;
                    }
                    if (bytes_read == 0) {
                        goto parse_data;
                    }
                    read_ok = InternetReadFile(
                        request, data + received, 0x400, &bytes_read);
                    received += bytes_read;
                }
                console_printf(
                    &console_log_queue, "Version Check: InternetReadFile failed.\n");
                console_printf(&console_log_queue, "Reason: %d\n", GetLastError());
                headers_length = 0x8000;
                InternetGetLastResponseInfoA(&response_error, data, &headers_length);
                console_printf(&console_log_queue, "Or: %s\n", data);
                goto cleanup;

            receive_overflow:
                console_printf(&console_log_queue,
                    "Warning: receiving too much data, breaking out..\n");
            parse_data:

                console_printf(
                    &console_log_queue, "Version Check: Beginning to parse data..\n");
                console_log_queue.flush_log("console.log");

                if (strstr(data, "<a href") == data) {
                    console_printf(&console_log_queue, "Data seems ok.\n");

                    char *link = 0;
                    char *newest = 0;
                    char *cursor = strchr(data, '"');
                    if (cursor) {
                        ++cursor;
                        link = cursor;
                        cursor = strchr(cursor, '"');
                        if (cursor) {
                            *cursor = '\0';
                            cursor = strchr(cursor + 1, 'C');
                            if (cursor) {
                                newest = cursor;
                                cursor = strchr(cursor, '<');
                                if (cursor) {
                                    *cursor = '\0';
                                    parsed = true;
                                    update_notice_url = strdup_malloc(link);

                                    sscanf(newest, "Crimsonland %d.%d.%d<", &version[0],
                                        &version[1], &version[2]);
                                    if (version[0] > 1 || version[1] > 9
                                        || version[2] > 94) {
                                        console_printf(&console_log_queue,
                                            "There is a newer version available. "
                                            "(v%d.%d.%d)\n",
                                            version[0], version[1], version[2]);
                                    } else {
                                        update_notice_url = 0;
                                    }
                                }
                            }
                        }
                    }

                    console_log_queue.flush_log("console.log");
                    console_printf(&console_log_queue, "Link: '%s'\n", link);
                    console_printf(
                        &console_log_queue, "Newest Version: '%s'\n", newest);
                    console_printf(&console_log_queue, "Local Version: '%s'\n",
                        "Crimsonland 1.9.93");
                } else {
                    console_printf(&console_log_queue, "Data not ok.\n", data);
                    console_printf(&console_log_queue, "Received: '%s'\n", data);
                }
                console_log_queue.flush_log("console.log");
                goto cleanup;

            } else {
                console_printf(
                    &console_log_queue, "Version Check: HttpOpenRequest failed.\n");
            }

        } else {
            console_printf(
                &console_log_queue, "Version Check: InternetConnect failed.\n");
        }
    }

cleanup:
    console_printf(&console_log_queue, "Version Check: CleanUp\n");
    delete data;
    if (request) {
        InternetCloseHandle(request);
    }
    if (connection) {
        InternetCloseHandle(connection);
    }
    if (internet) {
        InternetCloseHandle(internet);
    }

    if (parsed) {
        Sleep(300);
        online_sync_status = 5;
        Sleep(300);
        online_sync_status = 0;
        update_notice_pending = 1;
    } else {
        Sleep(300);
        online_sync_status = 6;
        update_notice_pending = 0;
    }

    console_printf(&console_log_queue, "endthread ()  (version check)\n");
    console_log_queue.flush_log("console.log");
    crt_endthread();
}
