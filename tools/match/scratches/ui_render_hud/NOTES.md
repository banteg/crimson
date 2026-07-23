# `ui_render_hud`

Native target: `crimsonland.exe` at `0x0041aed0` (7,081 bytes).

Live Binary Ninja evidence recovers the complete gameplay-facing HUD callback:
top frame, pulsing player hearts, weapon icons, health and ammo bars, Quest
clock/progress and stage banners, Rush/Typ-o-Shooter timer, smoothed Survival
XP, bonus slots, and per-player weapon-change popups.

This reconstruction intentionally preserves two native multiplayer details:
the second heart inherits player one's low-health pulse speed as its baseline,
and weapon-change popup rows advance only when a player's popup is active.
Bonus/pop-up layout starts at Y=78 and advances by 43 only when the XP panel is
present.

The dword at `0x004902fc` has exactly one native xref: an unconditional zero
store immediately before the quest spawn-count accumulation. It is retained as
`quest_progress_reserved_zero`; no stronger semantics are claimed.

The default VC6.5 `/O2 /GB /W3 /GR-` build scores **84.59%** with the exact
native `0x34`-byte stack frame and exact 1,824/1,824 instruction count. The
reference audit is 381 resolved, 0 unresolved, and 3 mismatched. Those three
are alignment fallout (one player-table/config read and the two quest-clock
format strings); no reference is hidden or force-accepted.

Remaining differences are ordinary old-MSVC register allocation, stack-slot
coloring, and a few equivalent control-flow layouts. In particular, the
reconstruction deliberately keeps the native ammo-class, XP smoothing, quest
fade, and popup timer branches in their evidenced source shape rather than
adding inert match-only scaffolding.
