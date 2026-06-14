# Matching Status

Regenerate with `uv run crimson match status --write tools/match/STATUS.md`.

Matched scratches: **12/12**.

## Images

| image | matched | scratches |
|---|---:|---:|
| crimsonland.exe | 5 | 5 |
| grim.dll | 7 | 7 |

## Scratches

| state | image | function | address | bytes | insns | match | prefix | build | note |
|---|---|---|---|---:|---:|---:|---:|---|---|
| match | crimsonland.exe | console_input_clear | 0x00401030 | 18 | 5/5 | 100.00% | 5/5 |  | smoke |
| match | crimsonland.exe | console_input_buffer | 0x00401050 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| match | crimsonland.exe | console_cmd_argc_get | 0x00401150 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| match | crimsonland.exe | vec2_length | 0x00417660 | 26 | 12/12 | 100.00% | 12/12 |  | x87-fsqrt |
| match | crimsonland.exe | game_sequence_get | 0x0041df60 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| match | grim.dll | grim_noop | 0x10001160 | 1 | 1/1 | 100.00% | 1/1 |  | smoke |
| match | grim.dll | grim_get_error_text | 0x10006ca0 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| match | grim.dll | grim_get_time_ms | 0x10006e40 | 6 | 2/2 | 100.00% | 2/2 |  | smoke |
| match | grim.dll | grim_get_frame_dt | 0x10006e60 | 33 | 9/9 | 100.00% | 9/9 |  | branch-x87 |
| match | grim.dll | grim_is_mouse_button_down | 0x10007410 | 38 | 11/11 | 100.00% | 11/11 |  | branch-call-stdcall |
| match | grim.dll | grim_get_mouse_x | 0x10007510 | 7 | 2/2 | 100.00% | 2/2 |  | smoke |
| match | grim.dll | grim_get_mouse_wheel_delta | 0x10007560 | 23 | 7/7 | 100.00% | 7/7 |  | branch-x87 |
