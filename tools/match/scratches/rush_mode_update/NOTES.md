# `rush_mode_update`

Native target: `crimsonland.exe` at `0x004072b0` (594 bytes, 136
instructions).

The recovered MSVC 6.5 `/O2 /GB` source is exact:

```txt
match=100.00% prefix=136/136 target_insns=136 candidate_insns=136 refs=51/0/0
```

## Recovered source shape

- Every call first forces both player slots to the assault rifle and 30 rounds,
  even when the console-open guard suppresses the rest of the update.
- The spawn cooldown is a signed integer. It loses
  `frame_dt_ms * config_player_count` each active frame and gains 250 ms per
  iteration, so a sufficiently negative value emits more than one pair.
- Each pair shares a clamped RGBA tint derived from
  `survival_elapsed_ms + 1`. The native constants are `1 / 120000`, `10000`,
  and the upward-rounded float `0x38d1b718` for the blue sine input.
- One alien enters from `terrain_width + 64` with a cosine-driven Y position;
  one spider enters from `-64` with a sine-driven Y position. Both use terrain
  half-height plus a 256-pixel oscillation.
- Both creatures switch to wide player orbit. The left spider additionally
  gains flag `0x80` and has its move speed multiplied by 1.4.
- In demo mode, a strict `quest_spawn_timeline > demo_time_limit_ms` cutoff
  clears the render-pass byte and starts the next demo segment.

The two position vectors, 16-byte tint aggregate, and integer tint time account
for the native 0x24-byte local stack. Reversing the commutative cooldown
operands recovers the native global-load order without changing semantics.

## Port parity

Python and Zig previously rounded the blue sine scale to the lower neighboring
float (`0x38d1b717`). Commit `e0454585c` uses the executable's exact constant in
both ports and adds a regression at elapsed time 63 ms, where the final tint
differs by one float ULP. The focused Python tests and all 482 Zig tests pass.
