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

VC6 now produces 64.46% with 243/241 normalized instructions and exact
66/0/0 reference agreement. The broad residual is register allocation: native
keeps the perk id in `EDI`, the cached player count in `EBP`, and loop state in
`ESI`; the natural reconstruction keeps the count in `ESI` and shrink-wraps an
`EBP` save around later loops. The Grim Deal XP update now reproduces the
native `mov`/`add`/`mov` sequence exactly; the two extra whole-function
instructions are the orthogonal shrink-wrapped `EBP` save and restore.
Initializing the count before the dispatcher raises the superficial score but
emits the load before the first comparison, contradicting the native per-exit
loads, so that shape is intentionally rejected. C and C++ modes,
the available VC6-family backends, `/GB` and `/G6`, standalone-global aliases,
and natural variable-lifetime spellings were checked. None recovers the native
allocation without artificial source, so the honest semantic WIP is retained.

The bounded player-loop mutation sweep records the two most direct native
control-shape probes rather than relying on manual register guesses. At Ammo
Maniac, `0x00405830..0x0040583e` compares the perk id, branches away, zeros the
player index, tests the cached player count in `EBP`, and only then materializes
the weapon-id cursor. Bandage repeats that ordering at
`0x004058b1..0x004058bf`: perk comparison, zeroed player index, `EBP` count
test, then the health cursor. The schema-1
`player-loop-entry-mutations.json` plan expresses each as an ordinary nested
condition, once with the existing semantic locals and once with block-local
names. Its SHA-256 is
`a8373fa8f9f44d23727ec464c07e78482aff6d55281448bfdc765e8325d692c0`.

All four one-site variants were recorded. Both Bandage forms are exactly
byte-neutral at `63.07053941908713%`, `558.1742738589212` weighted bytes,
241/241 instructions, a two-instruction prefix, and `63/0/0` references.
Both Ammo Maniac forms improve the prefix from two to four instructions but
fall to `56.84647302904564%` and `503.0912863070539` weighted bytes, a
`-55.08298755186729`-byte and `-6.224066390041494`-percentage-point
regression; they also lose 11 audited references (`52/0/0`) while retaining
241 instructions. No single-site variant improves the baseline, so no
interaction sweep or source edit is justified. The current combined
conditions therefore remain the stronger honest whole-function source even
though the native nested ordering stays visible as allocation debt.

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
64.46%, 243/241 instructions, and exact `66/0/0` references.

The scratch is classified `semantic-complete` with a `compiler` residual.
Fresh live Binary Ninja output confirms the complete immediate dispatcher and
each independent contract, XP, ammo, regeneration, Bandage, clip-size, and
Plaguebearer effect through `0x004055e0..0x00405955`. IDA and Ghidra
independently retain the same signature and six named helper calls. The first
localized mismatch is the native saved `EBP` and resulting stack offsets;
the candidate retains exact `66/0/0` audited references.

## Grim Deal assignment and allocation sweep

`local-allocation-mutations.json` records eight declaration-priority variants
and five natural Grim Deal assignment forms. All declaration orders are
byte-identical, ruling out source declaration order as the cause of the
`ESI`/`EBP` allocation split. Four assignment forms are neutral or regress.
Writing the explicit XP assignment before the health source statement makes
VC6 emit the exact native local sequence:

```text
fild; fmul; call __ftol; mov current_xp; mov health; add; mov new_xp
```

The retained form raises the weighted match by 12.3216 bytes, from 63.07% to
64.46%, and aligns three additional references without adding any unresolved
or mismatched reference. It grows the candidate from 241 to 243 instructions
because VC6 still adds the separately identified shrink-wrapped `EBP`
save/restore around later loops. That tradeoff is retained: the recovered
seven-instruction native update is exact, while the two extra instructions are
fully attributable to the existing register-allocation residual.

A complete follow-up interaction sweep of the Ammo Maniac and Bandage nested
entry forms evaluates all 8/8 single and paired variants on the improved
baseline. Bandage is byte-neutral; every Ammo form loses 54.8554 weighted
bytes and eleven aligned references. Scoping every unrelated branch local
independently and compiling the exact predecessor
`ui_render_keybind_help` before this function are also byte-identical. The
remaining exit requires a non-artificial allocation constraint beyond
declaration order, block scope, address-neighbor TU presence, or the two
native-looking loop-entry forms.
