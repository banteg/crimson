# console_command_unregister

Native target: `crimsonland.exe` at `0x00402530` (74 bytes).

The method resolves the target by name, handles the head separately, then
unlinks a later node as `cursor->next = cursor->next->next`. That ordinary
linked-list idiom is source-shape-significant and matches all 32 instructions
and references `1/0/0`.
