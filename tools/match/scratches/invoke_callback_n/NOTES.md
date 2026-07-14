# invoke_callback_n

Native target: `crimsonland.exe` at `0x004010f0` (42 bytes).

Nine callers use this four-argument `__stdcall` helper to invoke a C++ member
callback over a fixed-stride object array. The six calls in
`ui_menu_template_pool_init`, for example, construct eight 0x1c-byte slots at
a time through `ui_template_slot_ctor_noop`.

The pre-decrement loop spelling preserves the native zero-count guard and
matches all 21 instructions, full prefix. There are no static references; the
member callback is supplied indirectly by each caller.
