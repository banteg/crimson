# console_input_poll

Native target: `crimsonland.exe` at `0x401060` (140 bytes).

The helper always polls `IGrim2D_cpp::grim_get_key_char()`. When console input
is disabled it returns that character untouched, allowing the same polling path
to serve gameplay and text widgets. With console input enabled, it ignores
characters while a completed line is pending, treats carriage return as line
completion, handles backspace without underflow, and appends all other bytes.

The input buffer has a signed 1024-byte cursor limit. On overflow the cursor is
backed up one byte and the buffer is terminated in place. The recovered source
matches all 41 instructions and all 15 native references exactly.
