# ui_element_init_defaults

Native target: `crimsonland.exe` at `0x0044faa0` (173 bytes).

The initializer reports a null pointer, otherwise resets three resource ids to
`-1`, assigns the default `(233, 28)` / `(431, 68)` hover bounds, clears the
callbacks and runtime flags, and seeds the timeline and counter defaults.
The two bound assignments expose the original C++ two-float temporary shape.

The shared `ui_element_t` now identifies all three resource ids as texture
handles following the base, overlay, and secondary overlay vertex banks. In
particular, the former raw `+0x2ec` store is
`secondary_overlay_texture_handle`, immediately after the second eight-entry
0x1c-stride vertex bank. The typed field preserves the exact initializer.

Both native callers ignore EAX. The null path leaves formatted-output residue
there while the success path happens to retain the input pointer, so the
plausible API is `void`, not the decompiler's pointer return. The recovered
source matches all 40 instructions, full prefix, with all three references
aligned.
