# console_flush_log

Native target: `crimsonland.exe` at `0x00402860` (121 bytes).

This queue method opens the requested game-relative path in text-write mode and
serializes the newest-first linked log in oldest-first order. For each reverse
index it restarts at the head, walks to that node, and writes exactly the stored
string length without adding separators. It flushes and closes the file before
reporting success; open failure returns false.

The recovered quadratic traversal matches all 56 instructions, full prefix,
with all six file/path references aligned.
