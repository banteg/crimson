# camera_update

Native target: `crimsonland.exe` at `0x00409500` (910 bytes, 249
instructions).

MSVC 6.5 `/O2 /GB` reproduces the function exactly:

```txt
match=100.00% prefix=249/249 target_insns=249 candidate_insns=249 refs=76/0/0
```

## Recovered source shape

- An inactive shake timer clears both shake offsets. An active timer loses
  `frame_dt * 3.0f`; only a strictly negative result advances a pulse.
- A pulse decrements the remaining count. The last pulse sets the timer to
  zero but leaves the current offsets intact until the following update.
- Continuing pulses use a `0.1f` interval, shortened to `0.06f` while time
  scaling is active. Each axis independently draws
  `rand() % (pulses * 60 / 20) + rand() % 10` and a third random sign bit.
- Single-player camera focus follows `render_overlay_player_index` without a
  health test. Multiplayer focus selects the sole living player, averages the
  two living positions, or preserves the previous camera when neither lives.
- The source naturally exposes the native's repeated health tests as a small
  focus decision graph. No volatile accesses or synthetic side effects are
  needed.
- Shake is added after focus. Both axes clamp first to at most `-1.0f`, then to
  at least `screen_dimension - terrain_dimension`.

The pending y focus is assigned before the x shake update and then incremented
by the y shake. VC6 keeps that value on the x87 stack and folds the intermediate
store, producing the native common tail exactly.

## Port parity

The Python and Zig deterministic shake models already preserve the native
strict timer comparisons, last-pulse lifetime, six RNG calls, amplitude, sign,
and reflex interval. Their presentation camera code intentionally generalizes
the fixed 1-or-2-player native focus and configured-resolution clamp to the
current player list and runtime viewport; this scratch records the exact native
edge behavior for future parity work without changing that presentation policy.

All focus calculations now name the proven `player_state_t::position`
aggregate instead of its scalar compatibility aliases. This is byte-neutral:
the camera coordinator remains exact at 249/249 instructions and 76/0/0
references.
