# grim_get_config_float

Native target: `grim.dll` at `0x100071b0..0x100072b5` (261 bytes).

Verified with Microsoft Visual C++ 6.5 using the stock matcher profile: 88/88
normalized instructions, full prefix, and references `13/0/0`.

## Recovered source shape

- IDs `0x13f`, `0x140`, `0x141`, `0x153`, `0x154`, and `0x155` return the
  six `DIJOYSTATE2` axes scaled by `0.001f`.
- IDs `0x15f` and `0x160` forward to the direct mouse X/Y delta methods.
- A three-iteration loop maps `0x163..0x165` to indexed X delta and
  `0x168..0x16a` to indexed Y delta. Those compatibility methods currently
  ignore the supplied index, matching their separately recovered bodies.
- IDs at or below `0xff`, and every unmatched extended ID, return `0.0f`.

No inline assembly, volatile shaping, fake references, or forced addresses are
used.
