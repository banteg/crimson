# `perk_apply`

Native target: `crimsonland.exe` at `0x004055e0` (885 bytes).

Live Binary Ninja evidence recovers the immediate perk-effect dispatcher. It
increments player zero's count, applies a mutually exclusive first group, then
runs the independent contract, health, ammo, bandage, clip-size, and
plaguebearer effects in order.

The live x87 stores also pin the arithmetic boundaries: Thick Skinned rounds
its multiply before subtracting health (`0x004056cd..0x004056e6`), Breathing
Room stores each active creature lifecycle subtraction (`0x0040574a..0x00405752`),
and Bandage stores the multiplied health before its clamp (`0x004058d5..0x004058e3`).
The first dispatcher group assigns the cached configured-player count on every
exit: Instant Winner and Fatal Lottery join the common load at `0x00405796`,
Lifeline loads it after the creature walk, and the two health perks load it
before their loops. Random Weapon is an inner conditional in the final `else`,
followed by that same count assignment. This branch-complete source form
recovers the native 241-instruction extent.
Both ports now route these operations through the shared PC=24 helpers; the
Python port also stores Infernal Contract's literal as the native f32 value.
Infernal Contract addresses player slots zero and one explicitly at
`0x004057a2..0x004057f5`, rather than iterating `config_player_count`; both
ports now retain that two-slot scope in bug-compatible mode.

The reconstruction preserves the native quirks instead of the rewrite's
intentional fixes: Lifeline walks all 384 creature slots and directly disables
every other eligible entry; Breathing Room reduces every configured player and
ages each active creature; Bandage multiplies even dead-player health by a
1..50 roll; and Plaguebearer sets only player zero's flag. Death Clock clears
both regeneration counts before restoring positive player health, while Ammo
Maniac reassigns every configured player's current weapon.

Breathing Room and Bandage retain their native lifecycle- and health-field
induction cursors, but each now recovers the containing record with `offsetof`.
That exposes the named creature `active` field and the player's `pos_x` burst
origin instead of byte and float offsets. A combined shadow probe produced
identical VC6 output, including the 241 instructions and all 63 references.

VC6 produces 63.07% with 241/241 normalized instructions and exact 63/0/0
reference agreement. The broad residual is register allocation: native keeps
the perk id in `EDI`, the cached player count in `EBP`, and loop state in
`ESI`; the natural reconstruction keeps the count in `ESI` and shrink-wraps an
`EBP` save around later loops. The other two instructions are the equivalent
Grim Deal XP update (`mov`/`add`/`mov` versus a memory `add`). Initializing the
count before the dispatcher raises the superficial score but emits the load
before the first comparison, contradicting the native per-exit loads, so that
shape is intentionally rejected. C and C++ modes,
the available VC6-family backends, `/GB` and `/G6`, standalone-global aliases,
and natural variable-lifetime spellings were checked. None recovers the native
allocation without artificial source, so the honest semantic WIP is retained.

## Binary Ninja cursor recovery

This function was also being discarded by Binary Ninja's default analysis-time
heuristic. The name map now retains its complete IL and gives the compiler-
generated member cursors their semantic roles: sacrifice, Death Clock, and
Bandage health; configured-player weapon id; My Favourite Weapon clip size;
and the active-creature lifecycle walk. The lifecycle definition shares an
address with loop phi nodes, so the importer now supports a narrow
`source_name` selector rather than applying a type to an unrelated variable.

The negative subscripts that remain are truthful interior-pointer arithmetic:
for example, Bandage reaches player position from the health cursor, while
Breathing Room reaches the creature active byte from the lifecycle cursor.
No owning record type is forced onto either pointer. The candidate remains
63.07%, 241/241 instructions, and exact `63/0/0` references.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live Binary Ninja output confirms the complete immediate dispatcher and
each independent contract, XP, ammo, regeneration, Bandage, clip-size, and
Plaguebearer effect through `0x004055e0..0x00405955`. IDA and Ghidra
independently retain the same signature and six named helper calls. The first
localized mismatch is the native saved `EBP` and resulting stack offsets;
candidate and target still contain the same 241 instructions and exact
`63/0/0` audited references.
