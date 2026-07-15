# `perk_apply`

Native target: `crimsonland.exe` at `0x004055e0` (885 bytes).

Live Binary Ninja evidence recovers the immediate perk-effect dispatcher. It
increments player zero's count, applies a mutually exclusive first group, then
runs the independent contract, health, ammo, bandage, clip-size, and
plaguebearer effects in order.

The reconstruction preserves the native quirks instead of the rewrite's
intentional fixes: Lifeline walks all 384 creature slots and directly disables
every other eligible entry; Breathing Room reduces every configured player and
ages each active creature; Bandage multiplies even dead-player health by a
1..50 roll; and Plaguebearer sets only player zero's flag. Death Clock clears
both regeneration counts before restoring positive player health, while Ammo
Maniac reassigns every configured player's current weapon.

VC6 produces 62.50% with 239/241 normalized instructions and exact 61/0/0
reference agreement. The broad residual is register allocation: native keeps
the perk id in `EDI`, the cached player count in `EBP`, and loop state in
`ESI`; the natural reconstruction keeps the count in `ESI` and shrink-wraps an
`EBP` save around later loops. The other two instructions are the equivalent
Grim Deal XP update (`mov`/`add`/`mov` versus a memory `add`). C and C++ modes,
the available VC6-family backends, `/GB` and `/G6`, standalone-global aliases,
and natural variable-lifetime spellings were checked. None recovers the native
allocation without artificial source, so the honest semantic WIP is retained.
