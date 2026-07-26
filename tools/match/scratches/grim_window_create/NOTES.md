# grim_window_create

`grim_window_create` at `0x10002680` registers the `Crimson` window class and
creates either a topmost screen-sized popup or a centered adjusted window with
style `0x00cb0000`. The windowed dimensions come from the configured
backbuffer size; fullscreen dimensions come from `GetSystemMetrics`.

Creation failure records the native error, runs the shared teardown, and
returns false. Success performs the native show/update/focus/show/update
sequence and returns true.

The recovered function matches all 142 native instructions and all 46
references under MSVC 6.5 `/O2 /GB`. The class assignment also identifies
`0x100033b0` as `grim_window_proc`.
