#include <process.h>
#include <string.h>
#include <windows.h>
#include <wininet.h>

#include "crimsonland_highscore.h"

extern unsigned char config_highscore_date_mode;
extern unsigned char config_show_online_scores;
extern int config_selected_saved_name_slot;
extern char config_saved_name_0[][27];
extern unsigned char config_hardcore;
extern int quest_stage_major;
extern int quest_stage_minor;
extern int config_player_count;
extern char default_player_name[];
extern int online_sync_status;
extern unsigned char highscore_batch_sync_mode;
extern char s_empty_string;

extern "C" unsigned char game_is_full_version(void);
extern "C" int crt_rand(void);
extern "C" void j_highscore_load_table(void);
extern "C" void crt_endthread(void);

extern "C" void highscore_sync_worker(void *)
{
    console_printf(
        &console_log_queue,
        "beginthread () highscores thread.\n");
    console_log_queue.flush_log("console.log");

    unsigned char packed_record[0x40];
    highscore_record_t active_record_backup = highscore_active_record;
    char *headers =
        "Content-Disposition: inline; filename=\"test\"\r\n"
        "Content-type: application/octet-stream";
    online_sync_status = 1;
    bool success = false;
    HINTERNET internet = 0;
    HINTERNET connection = 0;
    HINTERNET request = 0;
    unsigned char score_count;
    DWORD bytes_read = 0;
    BOOL request_ok;
    BOOL read_ok;
    DWORD received;
    DWORD headers_length = strlen(headers);
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

    char *data = new char[0x8000];
    config_highscore_date_mode = 0;
    config_show_online_scores = 0;
    j_highscore_load_table();
    config_show_online_scores = 1;

    memset(data, 0, 0x8000);
    data[0] = 0x42;
    data[1] = 0x48;
    data[2] = (char)0xf3;
    data[3] = (char)0x85;
    if (config_selected_saved_name_slot == 0) {
        data[4] = 0;
    } else {
        data[4] = 1;
    }
    if (!game_is_full_version()) {
        data[4] = 0;
    }
    data[5] = 0;
    if (config_hardcore) {
        data[6] = 5;
    } else {
        data[6] = (unsigned char)config_game_mode;
    }
    data[7] = (unsigned char)quest_stage_major;
    data[8] = (unsigned char)quest_stage_minor;
    data[9] = (unsigned char)config_player_count;
    strcpy(
        data + 10,
        config_saved_name_0[config_selected_saved_name_slot]);

    DWORD payload_length = strlen(data + 10) + 11;
    highscore_record_t received_record;
    memset(&received_record, 0, sizeof(received_record));
    strcpy(received_record.player_name, default_player_name);
    received_record.flags = 0;
    received_record.sentinel_pipe = 0x7c;
    received_record.sentinel_ff = 0xff;
    received_record.random_tag = crt_rand() & 0x0fee050f;

    score_count = 0;
    if (game_is_full_version()) {
        char *write_cursor = data + payload_length;
        for (int index = 0; index < highscore_table_count; index++) {
            highscore_record_t *record = &highscore_table[index];
            unsigned char flags = record->flags;
            if (flags == 0 || (flags & 2) != 0 || (flags & 1) == 0) {
                if (highscore_submit_full_version_guard(record)) {
                    highscore_record_pack_for_submit(
                        record,
                        (highscore_record_t *)packed_record);
                    memcpy(write_cursor, packed_record, sizeof(packed_record));
                    payload_length += sizeof(packed_record);
                    write_cursor += sizeof(packed_record);
                    score_count++;
                } else {
                    console_printf(
                        &console_log_queue,
                        "Detected a potential illegal score: refusing to send it online.\n");
                }
            }
        }
    }
    if (game_is_full_version()) {
        data[5] = score_count;
    }

    internet = InternetOpenA("Crimsonland", 0, 0, 0, 0);
    if (!internet) {
        console_printf(
            &console_log_queue,
            "ONLINE Scores: InternetOpen failed.\n");
        goto cleanup;
    }

    {
        char server_address[64] = "scores.crimsonland.com";
        connection = InternetConnectA(
            internet,
            server_address,
            80,
            "guest",
            &s_empty_string,
            3,
            0x44000000,
            0x1289);
    }

    {
        char request_path[64] = "/scoring_v2_7.php";
        if (!connection) {
            console_printf(
                &console_log_queue,
                "ONLINE Scores: InternetConnect failed.\n");
            goto cleanup;
        }

        request = HttpOpenRequestA(
            connection,
            "POST",
            request_path,
            "HTTP/1.1",
            "none",
            accept_types,
            0x04000000,
            0x1289);
    }
    if (!request) {
        console_printf(
            &console_log_queue,
            "ONLINE Scores: HttpOpenRequest failed.\n");
        goto cleanup;
    }

    request_ok = HttpSendRequestA(
        request,
        headers,
        headers_length,
        data,
        payload_length);
    console_printf(
        &console_log_queue,
        "<-- Sending %d scores in %d bytes.\n",
        (unsigned int)score_count,
        payload_length);
    if (!request_ok) {
        console_printf(
            &console_log_queue,
            "ONLINE Scores: HttpSendRequest failed.\n");
        goto cleanup;
    }

    memset(data, 0, 0x8000);
    read_ok = InternetReadFile(request, data, 0x400, &bytes_read);
    received = bytes_read;
    while (read_ok
        && (int)(received + 0x400) <= 0x8000
        && bytes_read != 0) {
        read_ok = InternetReadFile(
            request,
            data + received,
            0x400,
            &bytes_read);
        received += bytes_read;
    }

    if (!read_ok) {
        console_printf(
            &console_log_queue,
            "ONLINE Scores: InternetReadFile failed.\n");
        console_printf(
            &console_log_queue,
            "Reason: %d\n",
            GetLastError());
        headers_length = 0x8000;
        DWORD response_error;
        InternetGetLastResponseInfoA(
            &response_error,
            data,
            &headers_length);
        console_printf(&console_log_queue, "Or: %s\n", data);
        goto cleanup;
    }
    if ((int)(received + 0x400) > 0x8000) {
        console_printf(
            &console_log_queue,
            "Warning: receiving too much data, breaking out..\n");
    }

    console_printf(
        &console_log_queue,
        "ONLINE Scores: Beginning to parse data..\n");
    if ((unsigned char)data[0] == 0x15) {
        unsigned int count_b = (unsigned char)data[2];
        unsigned int count_a = (unsigned char)data[1];
        int total_count = count_a + count_b;
        console_printf(
            &console_log_queue,
            "<-- %d scores (%d+%d) received in %d bytes.\n",
            total_count,
            count_a,
            count_b,
            received);

        int expected_length = total_count * 0x44;
        if ((int)received - 3 != expected_length) {
            console_printf(
                &console_log_queue,
                "! Invalid number of bytes received (%d should be %d).\n",
                received - 3,
                expected_length);
            data[0x200] = 0;
            console_printf(&console_log_queue, "->%s<-\n", data);
            goto cleanup;
        }

        console_printf(&console_log_queue, "- Saving scores...\n");
        if (total_count > 0) {
            char *read_cursor = data + 3;
            int remaining = total_count;
            do {
                unsigned char hardcore_marker =
                    config_hardcore ? 0x75 : 0;
                memcpy(&received_record, read_cursor, 0x44);
                received_record.flags = 1;
                received_record.hardcore_marker = hardcore_marker;
                highscore_save_record(&received_record);
                read_cursor += 0x44;
                remaining--;
            } while (remaining != 0);
        }
    } else {
        data[0x200] = 0;
        console_printf(
            &console_log_queue,
            "invalid feedback (%d bytes).\n",
            received);
        console_printf(
            &console_log_queue,
            "<-- (%d %d)\n",
            (unsigned char)data[0],
            (unsigned char)data[1]);
        console_printf(&console_log_queue, "->%s<-\n", data);
    }

    console_printf(
        &console_log_queue,
        "ONLINE Scores: Scores sent and received ok.\n");
    success = true;

cleanup:
    console_printf(&console_log_queue, "ONLINE Scores: CleanUp\n");
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

    j_highscore_load_table();
    unsigned char batch_mode = highscore_batch_sync_mode;
    highscore_active_record = active_record_backup;
    if (success) {
        if (!batch_mode) {
            Sleep(300);
        } else {
            Sleep(20);
        }
        online_sync_status = 5;
        if (!highscore_batch_sync_mode) {
            Sleep(300);
        } else {
            Sleep(20);
        }
        online_sync_status = 0;
    } else {
        if (!batch_mode) {
            Sleep(300);
        } else {
            Sleep(20);
        }
        online_sync_status = 6;
    }

    console_printf(
        &console_log_queue,
        "endthread ()  (High scores)\n");
    crt_endthread();
}
