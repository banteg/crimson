# grim_app_tick

`grim_app_tick` at `0x10002f80` is a `MyApp` method that samples
`timeGetTime`, accumulates elapsed milliseconds, and reports one tick whenever
the remainder reaches 30 ms. The first sample only seeds the previous tick.

The division remainder is retained, so delayed frames do not permanently skew
the cadence.

The recovered method matches all 29 native instructions and its
`timeGetTime` reference under MSVC 6.5 `/O2 /GB`.
