# grim_draw_text_mono

Plausible source shape is substantially recovered from the native 0x5c-byte
frame and live Binary Ninja evidence. The renderer lazily binds the mono-font
texture, applies `grim_font_scale` to its 16px advance, 28px line step, and
32px draw cells, and batches direct 16x16 atlas lookups. Byte `0xa7` suppresses
the next normal glyph's pre-advance. The three extended cases are composites:
`0xe4` draws `a` plus `"`, `0xe5` draws `a` plus `.`, and `0xf6` draws `o` plus
`"`.

The MSVC 6.5 `/O2 /GB` candidate matches 94.39% (298 candidate instructions
against 308 native instructions) with all 41 masked references resolved. The
only residual is honest optimizer shape: the candidate tail-merges the
identical `0xe4`/`0xf6` mark-UV and final-draw suffix, while the native keeps
ten duplicated instructions before converging at the final draw call. Switch,
early-continue, compiler-profile, scoped-local, and explicit common-tail forms
either preserve that fold or perturb otherwise exact frame/register code. No
alias symbol, volatile shaping, or other fakematch is used. Every native branch,
glyph lookup, composite draw, and state transition is represented, so the
scratch is classified as semantic-complete with a compiler residual.
