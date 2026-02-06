---
tags:
  - status-analysis
---

# Online high scores (WinINet protocol)

This is the classic 1.9.93 online leaderboard client logic as recovered from
static analysis. The implementation lives in two threads:

- High score submit/receive thread: `highscore_sync_worker` (`0x0042d0e0`)
  (logs "beginthread () highscores thread.")
- Version check thread: `statistics_update_check_worker` (`0x0042d8a0`)
  (logs "beginthread () (version check)")

The client uses WinINet (`InternetOpenA`, `InternetConnectA`, `HttpOpenRequestA`,
`HttpSendRequestA`, `InternetReadFile`) and sends/receives raw binary payloads.

## Shared state globals

- `online_sync_status` (`0x004d11f0`): cross-screen worker status (`0` idle,
  `1..5` progress/done, `6` failed).
- `update_notice_url` (`0x004d11f4`): URL staged by update-check worker.
- `update_notice_pending` (`0x004d11f8`): latch indicating update notice/open
  path is active.
- `update_notice_open_requested` (`0x00480838`): set when the in-UI
  "Get the update" button is pressed.

## HTTP endpoints

High scores:

- Host: `scores.crimsonland.com`
- Port: `80`
- Method: `POST`
- Path: `/scoringv27.php`
- HTTP version: `HTTP/1.1`
- Referrer: `none`
- Accept types array includes:
  - `image/gif`
  - `image/x-xbitmap`
  - `image/jpeg`
  - `image/pjpeg`
  - `application/vnd.ms-powerpoint`
  - `application/vnd.ms-excel`
  - `application/msword`
  - `application/x-comet`
  - `application/octet-stream`
  - `*/*`
- User agent: `Crimsonland`
- Username: `guest`
- Password: empty string
- Extra headers (exact string):
  - `Content-Disposition: inline; filename="test"\r\nContent-type: application/octet-stream`

Version check (adjacent logic, likely not needed for leaderboard server):

- Host: `www.crimsonland.com`
- Port: `80`
- Method: `POST`
- Path: `/ra_version.php`
- Same headers/accept list/user agent/guest user as above.

## High score submit payload (client -> server)

The client allocates a 0x8000 buffer and builds a binary payload. The payload
starts with a 10-byte header followed by a NUL-terminated player name, then a
sequence of 0x40-byte score records.

Header layout (offsets are from start of payload):

```
0x00 u8  0x42
0x01 u8  0x48
0x02 u8  0xF3
0x03 u8  0x85
0x04 u8  name_slot_valid (1 if config_name_slot_selected != 0 and full version; else 0)
0x05 u8  score_count (filled later; 0 in demo)
0x06 u8  mode_or_hardcore (config_hardcore ? 5 : config_game_mode)
0x07 u8  quest_stage_major
0x08 u8  quest_stage_minor
0x09 u8  config_player_count
0x0A ..  selected name (NUL-terminated, from config_saved_names[config_name_slot_selected])
```

Score records:

- Each submitted record is exactly `0x40` bytes.
- Records are built via `highscore_record_pack_for_submit`, which copies the base high score record
  fields (name + metadata) and zeroes bytes `0x3c..0x3f`.

- The client appends each record immediately after the name string.
- Total payload length = `0x0b + name_len + (score_count * 0x40)`.

Selection logic:

- Iterates the high score table (`DAT_00482b54` flags, `DAT_004c395c` count).
- Skips entries where flag bit 0 is set and bit 1 is not set. (Flags live at
  record offset `0x44`; see `docs/detangling.md` for meaning.)

- Calls `highscore_submit_full_version_guard` (illegal-score guard) per entry; on failure, logs
  "Detected a potential illegal score" and does not include that entry.

## High score response payload (server -> client)

The client reads the HTTP response body and expects a binary payload:

```
0x00 u8  0x15 (magic)
0x01 u8  count_a
0x02 u8  count_b
0x03 ..  records (count_a + count_b) * 0x44 bytes
```

- The client validates `payload_len - 3 == (count_a + count_b) * 0x44`.
- Each record is `0x44` bytes (bytes `0x00..0x43` of the high score record).
- For each record, the client pads the tail before saving:
  - `record[0x44] = 0` (flags)
  - `record[0x46] = 0x7c` (`'|'` sentinel)
  - `record[0x47] = 0xff`
- Records are saved via `highscore_save_record` (`0x0043b450`).

Note: The response record size (0x44) includes bytes `0x40..0x43` (date fields),
but the local save path overwrites date/checksum on write, so these bytes are
not critical for correctness.

## Practical server notes

- The client expects raw binary bodies, not JSON or text.
- Mismatched length or missing `0x15` magic will be logged as invalid feedback.
- The simplest compatible response is:
  - `0x15`, `count_a`, `count_b`, then `0x44 * (count_a + count_b)` bytes.
  - You can return zero records by sending three bytes: `0x15 0x00 0x00`.

## Open questions (need runtime confirmation)

- Exact semantics of header byte `0x04` (name slot / full version gate).
- Whether `count_a` vs `count_b` are interpreted as local vs internet scores.
- Any server-side validation expected for the 0x40-byte submitted records.

## Runtime wishlist (windows-vm)

If we want to validate with live captures:

- Hook `HttpSendRequestA` in the highscores thread and dump:
  - `lpOptional` buffer (payload) and `dwOptionalLength`.
  - `lpszObjectName` (path) and `lpszHeaders`.
- Hook `InternetReadFile` to dump the response body.
- Trigger: use the "Update scores" / "Receive scores" UI flow in the high
  scores screen and submit a fresh local high score.
