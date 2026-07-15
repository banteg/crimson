# quest_build_zombie_time WIP

Native target: `crimsonland.exe` at `0x00437d70` (152 bytes).

The builder emits paired zombie waves just outside the right and left arena
edges every eight seconds, from 1.5 through 89.5 seconds. Each wave contains
eight random zombies; the native intentionally leaves heading untouched.

The candidate has the same 50-instruction count and both references aligned,
but scores 60.00%. VC6 strength-reduces the entry index into a moving pointer
and schedules independent field stores earlier than native. This is retained
as honest source-shape evidence, not claimed as an exact match.
