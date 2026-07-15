# `hud_update_and_render`

Native target: `crimsonland.exe` at `0x0041ca90` (531 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 126/126
normalized instructions, full prefix, and masked references `49/0/0`.

Live Binary Ninja reveals three responsibilities: calculate and complete the UI
transition alpha, draw the tracked Doctor-perk creature's clamped health bar,
and select the five HUD panels for Quest, Survival, Rush, Typ-o-Shooter, or the
fallback mode. The final HUD render is suppressed during demo playback and
receives the transition alpha as its sole argument.

The tracked-creature bar uses an ordinary constructed world position, a second
constructed bar position, and an RGBA value. VC6 keeps the first position's X
component live on x87 while reserving the full object slot, which explains the
native stack layout. The native call also proves the corrected
`ui_render_hud(float transition_alpha)` prototype.
No inline assembly, volatile state, dummy references, or dead expressions are
used.
