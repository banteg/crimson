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

The default VC6.5 `/O2 /GB /W3 /GR-` build scores **85.64%** with the exact
native `0x34`-byte stack frame and exact 1,824/1,824 instruction count. The
reference audit is 385 resolved, 0 unresolved, and 0 mismatched. Writing the
quest-clock leading-zero case as the fallthrough branch matches the native
basic-block order and resolves both clock-format references. Keeping the
player-zero weapon-id expression inside both icon-layout branches lets VC6
hoist the common load in the native order, removing the final audit mismatch
and 73.76 fuzzy-gap bytes. No reference is hidden or force-accepted.

Remaining differences are ordinary old-MSVC register allocation, stack-slot
coloring, and a few equivalent control-flow layouts. In particular, the
reconstruction deliberately keeps the native ammo-class, XP smoothing, quest
fade, and popup timer branches in their evidenced source shape rather than
adding inert match-only scaffolding.

The HUD ammo-class lookup now names the canonical
`weapon_storage_entry_t::ammo_class` field instead of multiplying the weapon
id by a raw 31-dword row stride. The source-only type correction is
byte-neutral. With the branch-order recoveries above, final validation remains
1,824/1,824 instructions at 85.6360% with `385/0/0` references.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live Binary Ninja decompilation confirms the heart, weapon/ammo, Quest,
timer, Survival XP, bonus-slot, and weapon-popup paths through the native
`0x0041aed0..0x0041ca79` extent. IDA and Ghidra independently retain the same
signature and six named helper calls. The first localized mismatch is only the
native `[esp+0x1c]` versus candidate `[esp+0x18]` temporary slot; the next
regions likewise preserve the same operations and audited references in
different legal stack slots.
