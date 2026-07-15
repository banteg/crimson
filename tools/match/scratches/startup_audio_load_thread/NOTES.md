# `startup_audio_load_thread`

Native target: `crimsonland.exe` at `0x0042b250` (63 bytes).

Live Binary Ninja evidence identifies the sole caller as the `_beginthread`
launch in `game_startup_init`. The callback initializes music and SFX, then
publishes the intro-render and async-load-ready latches before terminating the
CRT thread.

Exact verified match: 100.00%, with 14/14 normalized instructions and masked
references `11/0/0`, using Microsoft Visual C++ 6.5 with
`/O2 /GB /W3 /GR-`.

The native body uses one `AL = 1` value for both latch stores and tail-calls
`crt_endthread`, exactly as emitted by the recovered void callback.
