# mod_api_core_printf

Native target: `crimsonland.exe` at `0x40dfc0` (52 bytes).

This is vtable slot `0x00`, not the similarly shaped helper at `0x40e000`.
Because it is a variadic C++ method, VC6 places `this` on the stack and uses a
caller-cleaned return. It formats into the shared buffer at `0x4d9f00`, passes
that buffer to `mod_api_debug_printf`, and then queues the same line in
`console_log_queue`.

Natural member source matches all 14 instructions and all 7 references
exactly. The function split and buffer name are recorded in both repository
maps and the live Binary Ninja database.
