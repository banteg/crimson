# console_cmd_exec

Native target: `crimsonland.exe` at `0x00401250` (236 bytes).

The `exec` command requires exactly one script argument, opens it in text mode,
reports success or failure, and reads at most 510 characters per line into a
512-byte global buffer. It strips the first newline, explicitly terminates byte
511, and executes accepted lines through the console queue.

The native filter rejects any line whose first character is `/`, whose second
character is `/`, or whose first character is newline, null, or `#`. The two
slash tests are independent; preserving that unusual policy matches all 72
instructions, full prefix, with all 28 references aligned.
