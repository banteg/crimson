# `ui_text_input_render`

Native target: `crimsonland.exe` at `0x004413a0` (3,504 bytes).

Verified exact: **924/924 normalized instructions**, with **243 resolved
references**, no unresolved references, and no reference mismatches.

Despite the inherited symbol, live Binary Ninja evidence and all five recovered
call sites show that this is the high-score/result-card renderer, not the
14-byte text-input widget renderer. Its arguments are a two-float position,
a `highscore_record_t`, the transition alpha, and a displayed rank.

The reconstruction covers the player/source/date header used on the high-score
screen, score/rank formatting, quest experience versus elapsed time, the clock
gauge, most-used weapon icon/name, frag and hit-rate statistics, phase-specific
result-card suppression, and the three eased hover tooltips. The source keeps
the historical manifest symbol so existing caller scratches and reports remain
stable.

The final source shape also recovers two characteristic C++ idioms: an
aggregate RGBA assignment from the shared render tint before overriding alpha,
and a small inlined two-float position constructor for the player-name
underline. Both independently reproduce the otherwise unexplained VC6
instruction scheduling without artificial casts or padding.
