# `gameplay_render_world`

Native target: `crimsonland.exe` at `0x00405960` (625 bytes).

Verified with Microsoft Visual C++ 6.5 using `/O2 /GB /W3 /GR-`: 184/184
normalized instructions, full prefix, and masked references `56/0/0`.

Live Binary Ninja reveals the world render coordinator. It computes transition
alpha, revokes unavailable or expired temporary weapons, applies the native
game-state transition visibility policy, and clamps alpha before rendering.
Dead-player overlays are drawn before creatures and living-player overlays
after them; projectiles receive the transition alpha, bonuses follow, and a
positive screen fade draws the final black fullscreen overlay.

The transition policy reads the current state, pending state, and transition
latch directly. That simple source shape produces the native AL/ECX/EAX
allocation and lets VC6 schedule the pending-state load between the latch test
and branch without disturbing flags.

The callsite proves the corrected `projectile_render(float transition_alpha)`
prototype. No inline assembly, volatile state, dummy references, or dead
expressions are used.

## Port parity

Before rendering, native compares `quest_unlock_index_full` with 40 at
`0x00405982` and replaces Splitter Gun id 29 in both fixed player slots through
`weapon_assign_player` at `0x004059a0` and `0x004059b4`. Both ports now run this
entitlement guard in the deterministic end-of-step path. Bug-compatible mode
retains the two-slot scope, while corrected mode extends it to generalized
co-op players. Zig's adjacent Blade Gun and Shrinkifier revocations now also
use the state-aware assignment path, preserving native weapon-usage accounting.
The guard precedes `bonus_render`'s Telekinetic pickup and the later ordinary
`bonus_update`, so a newly collected locked weapon survives until the next
frame; both deterministic pipelines retain that ordering directly.
