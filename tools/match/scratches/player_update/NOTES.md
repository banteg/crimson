# `player_update` WIP

Native target: `crimsonland.exe` at `0x004136b0` (16,257 bytes).

This is the central per-player simulation routine. Live Binary Ninja evidence,
the raw Ghidra export, and the existing parity port agree on the recovered
phases:

- console short-circuit and per-player mouse/aim capture;
- previous-position capture and the dead-player timer path;
- speed-bonus application and the low-health blood/SFX pulse;
- muzzle-flash and weapon cooldown decay;
- Man Bomb's alternating eight-projectile ring;
- Living Fortress timer accumulation and 30-second clamp;
- Fire Cough's randomized fire-bullet shot and sprite flash;
- Hot Tempered's alternating plasma ring;
- the shared spread-damping scalar update;
- mouse-to-point, dual-axis, relative-direction, and keyboard movement modes,
  including acceleration, the weapon speed cap, and spawn avoidance;
- demo/AI auto-target validation plus the full 384-creature nearest-target scan
  with its 64-unit replacement hysteresis;
- demo autoplay movement, including center-orbit fallback, target pursuit inside
  the 300-unit arena radius, center return outside it, heading smoothing,
  acceleration/deceleration, weapon speed capping, and spawn avoidance;
- mouse, analog-stick, joystick-cursor, keyboard, POV, and smoothed auto-target
  aim updates;
- manual reload, Sharpshooter cooling, Anxious Loader, Stationary Reloader, and
  Angry Reloader's projectile ring;
- normal and perk-funded fire gates, Regression Bullets/Ammunition Within
  costs, muzzle smoke, projectile ownership, randomized spread, and shared
  weapon cooldown/SFX setup;
- the dedicated Fire Bullets replacement path, including its paired SFX,
  single-pellet fallback cadence, per-weapon pellet count, signed shot jitter,
  muzzle sprite, Sharpshooter spread rule, and ammo bypass;
- Alternate Weapon's complete field swap, reload SFX, cooldown penalty, and
  200-millisecond reload-key debounce;
- direct projectile dispatch for pistol, assault rifle, SMG, plasma, ion,
  pulse, blade, splitter, minigun, plague, rainbow, and Bubblegun families,
  including Shrinkifier muzzle effects and the three flame emitters;
- the Shotgun, Sawed-off Shotgun, Jackhammer, Gauss Gun, Gauss Shotgun, Ion
  Shotgun, and Plasma Shotgun pellet loops, including their per-projectile
  spread and speed randomization;
- Rocket Launcher, Seeker Rockets, Mini-Rocket Swarmers, and Rocket Minigun
  secondary-projectile dispatch, including the ammo-scaled swarmer fan; and
- movement-phase normalization, speed-bonus removal, terrain clamping, and the
  final muzzle-flash clamp.

Known missing work:

- exact local lifetimes/register allocation around the recovered control paths.

The entry death arm is now pinned across both ports. Live instructions at
`0x004136f9..0x0041372c` capture the previous position, test health, store the
float32 result of `death_timer - frame_dt * 20.0f`, and return before the
low-health, muzzle-flash, cooldown, perk, or movement phases. Python now keeps
the x87 PC=24/store boundary on the death decrement. Zig previously narrowed
that decrement correctly but decayed muzzle flash before testing health; its
preprocess path now leaves every other live-player field untouched for a dead
player.

The adjacent low-health pulse is also recovered through the three native blood
effect calls. Instructions `0x00413795..0x004137ed` evaluate
`(aim_heading + 1.5707964f) - 0.5f`, multiply both wide trig results by
`-6.0f`, add the player position, and pass that offset point to all three
calls. Both ports now preserve those PC=24 arithmetic boundaries; Zig had
previously emitted the blood effects directly at the player center.

Man Bomb stores its timer after the frame add at `0x004138d3` and after the
interval subtraction at `0x0041399d`; Living Fortress stores its timer after
the add at `0x004139d3` before comparing against 30. Both ports now preserve
those PC=24 boundaries. In particular, repeated 60 Hz updates leave Man Bomb
at `3.9999969` on frame 240 and fire its projectile ring on frame 241, rather
than accumulating host-double residue and firing one frame early.

The reload paths at `0x00415107..0x00415117` and
`0x004151e6..0x004151f6` round `reload_scale * frame_dt` at PC=24 before
subtracting it from the stored reload timer. Both ports now make that staging
explicit. Python had instead kept the scaled frame delta wide: at 38 Hz, a
stationary 1.5-second reload reached zero on frame 19, while native retains
`4.172325e-7` until frame 20. The adjacent Anxious Loader subtract/multiply,
half-reload comparison, and preload-underflow arithmetic now preserve the same
observed boundaries.

This scratch is intentionally an honest partial reconstruction. It does not
use volatile state, dead expressions, dummy references, inline assembly, or
layout-only gotos.

The remaining scalar creature-position aliases in target validation, demo
movement, and smoothed auto-aim now use the canonical
`creature_t::position` aggregate. The final Y bounds tests likewise keep their
evidenced direct player-record access while naming `player_state_t::position`,
and the Fire Cough smoke velocity uses `effect_template_t::velocity`. A
whole-function shadow compile is byte-neutral at 4,019/4,206 instructions,
54.86%, a seven-instruction prefix, and `736/0/11` references. This is type
recovery only and remains the baseline before the control-flow recovery below.

Two adjacent source shapes are now pinned by live Binary Ninja instructions.
Alternate Weapon's debounce at `0x004157da..0x004157f0` tests the integer
cooldown with `test`/`jle`, subtracts `frame_dt_ms`, stores the result, and
uses `test`/`jg` to skip the swap while the result stays positive. Expressing
the two equivalent integer predicates as `<= 0` restores that native branch
shape. After the normal/perk readiness gate, `0x0041591e..0x00415937`
snapshots `player->aim_heading` before calling the fire-key input method.
Sequencing that snapshot after readiness and before the key/auto-fire operand
preserves the native short-circuit ordering. Together these changes raise the
score from 54.86% to 55.27%, reduce the weighted gap from 7,338.8743 to
7,271.6721 bytes, and improve references from `736/0/11` to `742/0/9`,
without changing the 4,019 candidate instructions or seven-instruction
prefix.

The mode-1 turn and movement inputs at `0x0041445e..0x00414624` test each
`grim_is_key_active` result directly, then use the single-player alternate
`grim_is_key_down` call as the second short-circuit operand. The previous
scratch stored those byte-sized results in four `int` temporaries before
testing them. Expressing the native predicates directly removes the
unsupported zero-extension/stack lifetimes and preserves all four input
behaviors. This raises the whole-function score from `55.27%` to `56.42%`,
reduces the weighted gap from `7,271.6721` to `7,084.8627` bytes, reduces the
candidate from 4,019 to 4,011 instructions, and improves references from
`742/0/9` to `758/0/7`.

The mode-1 displacement scale is now complete. MLIL at `0x00413dfb`
identifies the native `[esp+0x1c]` value as the player's
`speed_multiplier`. All three mode-1 arms multiply both heading components by
that value before the signed `25.0f` scale: forward at
`0x004147f8/0x00414813`, backward at `0x0041470b/0x00414726`, and
deceleration at `0x00414636/0x00414651`. The scratch previously omitted those
six multiplies even though the other movement modes already used the same
scalar. Restoring them grows the candidate from 4,011 to 4,015 instructions
and improves references from `758/0/7` to `760/0/5`. The whole-function fuzzy
score falls from `56.4196%` to `56.2219%` because VC6 assigns the scalar to a
different stack slot and tail-merges the adjacent trig paths; the weighted gap
therefore grows by `32.1477` bytes, from `7,084.8627` to `7,117.0105`.
The native-proven behavior is retained rather than optimizing the heuristic by
leaving executable movement scaling absent.

Two natural aggregate shapes were measured and rejected after that correction.
Carrying a mode-local pointer to `move_delta` through the shared movement call
falls to `55.7042%` with 4,016 instructions and `752/0/6` references. Carrying
a pointer to `player->movement` through the three arms falls to `55.8677%`
with 4,017 instructions and `750/0/5` references. Both preserve semantics but
perturb unrelated allocation more than the direct field/aggregate source.

Three adjacent source-shape probes were rejected. Nesting the readiness and
fire-input gates exactly as the native decompile presents them was byte-neutral.
Moving the mode-1 phase-sign initialization to its first source use was also
byte-neutral. Consuming Fire Cough's `vec2_sub` return pointer directly did
recover that local native lifetime, but perturbed the whole-function allocation,
lowering the score to `56.20%` and the prefix from seven instructions to two.

The selected aim-screen aggregate now has an ordinary destination pointer at
the entry copy. This matches the native `0x004136c5..0x004136e3` schedule:
VC6 forms the player-record index between the two adjacent aim-screen stores
instead of hoisting the `ui_mouse_y` load ahead of both stores. The source
still performs one typed two-float aggregate copy, with no scalar bit casts or
artificial dependency. It raises the score from `56.2219%` to `56.2705%`,
reduces the weighted gap from `7,117.0105` to `7,109.1005` bytes, and improves
references from `760/0/5` to `762/0/5`; the 4,015/4,206 instruction counts and
seven-instruction prefix are unchanged.

A systematic codegen audit requested 59 profiles. The 45-profile compiler
matrix covered every installed backend (`msvc6.0`, `msvc6.5`, `msvc6.5pp`,
`msvc6.6`, and `msvc7.0`) across optimization level, `/GB`/`/G5`/`/G6`,
inlining, frame-pointer, and exception variants. Fourteen additional VC6.5
checks covered `/Op`, `/Oi-`, `/Ob0`, `/Os`, `/Ot`, `/Og-`, `/Gf`, `/Gy`,
debug-info, packing, and unsigned-char toggles. VC6.0, VC6.5, and VC6.6 emit
the same best code; patched VC6.5 falls to `48.22%`, VC7.0 to `35.11%`, and
every non-neutral flag regresses. No `scratch.conf` override is justified.
Entry probes also found moving previous-position storage to a brace initializer
and using pointer/helper aggregate copies byte-neutral; scalarizing the
retained position preserved fuzzy bytes but degraded the audit to `731/0/14`.

The recorded mutation sweeps isolate the remaining previous-position lifetime
without retaining a codegen-only source trick. The schema-1
`position-snapshot-mutations.json` plan has SHA-256
`32132d6096474cda1e8ab00a5fc3a4fa8195e81b1a1e346de4d7653272f86e2c`.
Its one-site run evaluated all `8/8` variants, and its `--max-changes 2`
interaction run evaluated all `23/23` variants (`8/8` one-site plus `15/15`
two-site, with no unevaluated combinations). All five declaration, aggregate,
const, and brace-initializer snapshot shapes were exactly byte-neutral, both
alone and in combination with the winner. Reversing either stationary
comparison operand order ranked last at `9,143.9445` weighted bytes, a
`-3.9550`-byte and `-0.024328`-percentage-point regression from the recorded
baseline, with instruction and reference counts unchanged.

The unique winner reads the stationary comparison through the canonical
`player->position` fields. Live target instructions load X through the retained
position alias at `0x0041506f` (`fld [esi]`) and Y through the player record at
`0x00415084` (`fld [edi+0x18]`). The retained source makes VC6 select that same
mixed native access shape: candidate offsets `0x17e0` and `0x17f5` emit
`fld [esi]` and `fld [edi+0x18]`, respectively; only the still-unmatched frame
slots differ (`[esp+0x48]/[esp+0x4c]` versus native
`[esp+0x30]/[esp+0x34]`). The winner source SHA-256 is
`7823c46d831ed2fb77432ab100bf4627595c5958fe3478c7907be8a4f2d4f227`.
It raises weighted bytes from `9,147.899525605157` to
`9,214.078016769960`, reduces the gap from `7,109.100474394843` to
`7,042.921983230041`, and raises the ratio from
`56.27052669991485%` to `56.67760359703488%`. That is
`+66.178491164803` weighted bytes and `+0.407076897120`
percentage points; candidate coverage grows from 4,015 to 4,023 instructions
and references from `762/0/5` to `766/0/5`, while the seven-instruction prefix
is unchanged.

A second live-instruction control plan,
`stationary-comparison-native-mutations.json`, has SHA-256
`c8371651268d5ee59739fa2155058ba773cce6a0559ffcf04e8760d45f983123`
and evaluated all `8/8` variants against the retained winner. All three honest
pointer type/const shapes were byte-neutral. The opposite mixed access
(`player->position.x` then `player_position->y`) lost `3.9511` weighted
bytes; spelling the apparently native mixed access directly lost `62.2235`
bytes, eight instructions, and four references because it changed
whole-function allocation; aliasing both components returned exactly to the
old `56.2705%` baseline; and the reversed/snapshot-first forms lost
`70.1335` bytes. No variant improved, so no second interaction run or source
change was warranted. A fresh entry region still shows native storing the
snapshot before the health x87 comparison at `0x004136f3..0x0041370d`, while
the candidate delays those stores across the compare; the complete neutral
snapshot ranking leaves that residual visible rather than forcing it.

Current local score:

```txt
match=56.68% prefix=7/4206 target_insns=4206 candidate_insns=4023 refs=766/0/5
first_target=jne L3f7a
first_candidate=jne L3d4e
```

Recovery is classified `semantic-complete` with a `compiler` residual. The
live Binary Ninja bundle retains all 485 native basic blocks,
and the source covers every recovered phase listed above. The five remaining
reference mismatches are alignment/scheduling debt rather than absent
operations. The candidate resolves 766 references and emits 4,023 of 4,206
native instructions; the residual instruction-count gap is concentrated in
register allocation, x87 lifetime, and compiler tail-merging differences
across already-recovered branches. All five mismatches remain visible and
unaliased, so this classification does not mask an address disagreement.

The Fire Cough muzzle sprite at `0x00413c0b..0x00413c38` writes the four
adjacent color components only after `fx_spawn_sprite` returns. Naming the
existing `effect_color_t` subobject at that point preserves that natural
aggregate source boundary and raises the whole-function score from `54.81%`
to `54.86%` without changing the exact `0x48` frame, instruction count, or
reference audit. Copying a separately initialized color value instead grows
the frame to `0x50`, adds ten candidate instructions, and falls to `48.60%`;
re-indexing the player table through additional scoped pointers likewise grows
the frame or perturbs unrelated allocation, so neither compiler-shaped probe
is retained.

## Binary Ninja control-flow retention

The saved database had released all advanced analysis for this 16,257-byte
function: its 485 disassembly basic blocks remained, but LLIL, MLIL, and HLIL
were all unavailable. A `never_skip` override alone did not rebuild them after
reanalyzing. Binary Ninja also requires one live
`request_advanced_analysis_data()` retention request for a function whose IL
has already been released.

The map importer now makes that request exactly once when a `never_skip`
function has no LLIL, then reanalyzes it. The `player_update` map row durably
opts into that policy. A live replay restores LLIL, MLIL, and HLIL for the
complete 485-block player simulation, including its movement, targeting,
reload, perk, and weapon-dispatch branches, without changing source or matcher
results.

Two additional type/source-shape leads were measured after the movement
recovery and rejected. Declaring the four alternate movement/turn key globals
as bytes follows several native byte loads, but VC6 adds eight zero-extension
instructions elsewhere in the dispatcher: the result falls to 54.73% with
4,027 candidate instructions (`refs=736/0/10`). Splitting the entry mouse-to-
aim aggregate copy into two float assignments instead selects x87 loads and
stores, falling to 54.76% and `refs=734/0/11`. The existing integer-shaped
two-float aggregate copy and integer key declarations therefore remain the
strongest whole-function source model; neither local clue justifies weakening
the surrounding native shape.

The point-control movement arm at `0x00414035..0x004141ad` retains its own
two-float displacement value through acceleration, deceleration, and the
shared spawn-avoidance call. The adjacent dual-axis arm uses a different
source value even though both paths ultimately occupy the native
`[esp+0x48..0x4c]` slot. Reusing the generic movement vector only in
point-control mode preserves the evidenced non-overlapping temporary lifetime,
prevents VC6 from tail-merging the two mode bodies, and keeps the exact native
`0x48` frame. It grows candidate coverage from 3,928 to 4,019 instructions,
improves reference agreement from `710/0/9` to `736/0/11`, and raises the
whole-function score from `53.01%` to `54.81%`. A separate scoped vector
revealed the same missing code but grew the frame to `0x4c`; scalar aim copies
and declaration-order changes were also measured and rejected.

The weapon-power-up cooldown at `0x0041385f..0x00413892` tests the active
positive timer as its fallthrough arm, subtracting `frame_dt * 1.5f`, and
branches the expired timer to the ordinary `frame_dt` subtraction. Restoring
that natural positive condition raises the score from `52.96%` to `53.01%`
and aligns one additional reference without changing the frame or instruction
count.

The inlined Long Distance Runner acceleration predicate now follows the native
positive arm. At the movement sites, including `0x0041467b..0x004146cf` and
the autoplay site at `0x00414d8c..0x00414de4`, native tests the perk count
against zero, leaves the extended-speed arm as the fallthrough, and branches a
non-positive count to the ordinary-speed arm. Expressing that as `count > 0`
before the fallback removes the unsupported function-wide `EBX == 1`
lifetime. In particular, VC6 can no longer merge mode 2's movement call with
the autoplay tail: the candidate now retains all three native
`player_apply_move_with_spawn_avoidance` callsites. The positive branch order
also raises reference agreement from `691/0/11` to `709/0/9` and the
whole-function score from `52.22%` to `52.96%`, while preserving the exact
`0x48` frame.

The perk-funded shot charge at `0x0041595c..0x00415a08` tests Regression
Bullets positively and lays out its experience-spend arm before the
Ammunition Within damage fallback. The earlier equivalent reconstruction
inverted that outer test, so VC6 emitted the fallback first and tail-merged
the two branch-local float-to-int conversions. Restoring the native
positive-condition nesting recovers both `__ftol` calls, both experience
stores, and the native call order without artificial control flow. It adds
three candidate instructions, improves reference agreement from `685/0/13`
to `691/0/11`, and raises the whole-function score from `51.99%` to `52.22%`
while preserving the exact `0x48` frame.

The muzzle-effect direction lifetimes are now pinned across the normal weapon
dispatcher. Shrinkifier, Pistol, Assault Rifle, and SMG store each wide cosine
or sine result into the retained direction component and immediately multiply
that same x87 value by `25.0f` at `0x00415f54..0x004160a3`,
`0x00416138..0x0041616b`, and `0x0041676b..0x0041679a`. Interleaving those
ordinary component assignments recovers the native stores and prevents VC6
from collapsing the adjacent Shrinkifier/Pistol projectile and first-sprite
calls. Jackhammer at `0x004163df..0x00416406` and Rocket Minigun at
`0x00417141..0x00417168` do not retain a direction vector at all; writing
their single-use scaled trig results directly removes four unsupported local
stores. Together these changes add the missing direct projectile callsite,
recover the native first-sprite duplication, preserve the exact `0x48` frame,
improve reference agreement from `681/0/14` to `685/0/13`, and raise the
whole-function score from `51.77%` to `51.99%`.

The auto-target aim approach at `0x004156ca..0x004156d4` multiplies the
target distance by `6.0f` before applying `frame_dt`. Keeping that ordinary
source grouping explicit as `(scalar * 6.0f) * frame_dt` preserves the native
constant/reference order. It leaves the instruction count and whole-function
score unchanged while improving reference agreement from `679/0/16` to
`681/0/14`.

The native function keeps two related addresses live for essentially the
entire frame: `EDI` is the selected `player_state_t`, while `ESI` is the
address of its adjacent `pos_x`/`pos_y` pair. The earlier flattened scratch
re-derived those fields from `player` at each use, so VC6 assigned the two
bases to the opposite registers and repeatedly lost the native value lifetime.
Materializing one ordinary `float *player_pos = &player->pos_x` alias and using
it for coordinate reads, writes, and vector arguments recovers that evidenced
source shape. It adds 73 native-shaped candidate instructions, raises the
whole-function score from `39.13%` to `49.05%`, and improves reference
agreement from `594/0/32` to `667/0/16` without changing behavior or the exact
`0x48` frame. The remaining first mismatch is local scheduling around the
previous-position copy, not a missing simulation path.

The live Binary Ninja split variable produced after the final
`index * sizeof(player_state_t) + player_state_table` address calculation is
now explicitly a `player_state_t *`. This replaces raw `EDI + 0x10..0x35c`
accesses with named player fields throughout the decompilation while leaving
the preceding strength-reduced `index * 3 * 0x120` calculation visible. `ESI`
retains its independently evidenced `vec2f_t *` position view. Both
instruction-scoped types are persisted in the replay map at the native
`add edi, player_state_table` and `lea esi, [edi+0x14]` definitions, so a
fresh Binary Ninja database does not regress to anonymous offset cursors.

That same address now has a `vec2f_t *player_position` view for field access,
while the raw pointer remains only for legacy helper arguments whose
declarations have not yet been widened. This replaces 174
`player_pos[0]`/`player_pos[1]` aliases across movement, targeting, weapon
spawns, and bounds handling with named `x`/`y` fields. A whole-function shadow
probe is exactly neutral at 4,019 candidate instructions, `54.81%`, a
7-instruction prefix, and references `736/0/11`, confirming that the stronger
type is source recovery rather than a codegen trick.

The native weapon dispatch retains 33 direct `projectile_spawn` callsites and
four `fx_spawn_secondary_projectile` callsites. The earlier candidate emitted
only 26 and three: reusing one function-wide position temporary let VC6 merge
otherwise distinct one-shot weapon tails. Native repeatedly materializes the
same two-float physical stack slot in those branches while still retaining
their separate calls, which is evidence for short-lived source values whose
storage was coalesced after their lifetimes ended. Giving every simple direct
or secondary weapon arm its own scoped `spawn_pos`, then recovering the
Shrinkifier/Pistol muzzle-direction lifetimes, now retains all 33 direct calls
and all four secondary calls without growing the exact `0x48` frame. The
candidate currently has 26 direct `fx_spawn_sprite` relocations against 25
native callsites; that residual is left honest rather than forcing another
tail merge with layout-only control flow or artificial dependencies.

The muzzle-flash decay at `0x00413842..0x0041384e` takes the address of
`player+0x2fc`, spills it to `[esp+0x24]`, and updates through that pointer.
The final clamp reloads the same pointer at `0x00417611`. Retaining an ordinary
source alias for this long-lived field adds four native-shaped candidate
instructions and one aligned reference, raising the match from `51.54%` to
`51.71%` without changing the exact `0x48` frame. A C++ reference compiled
identically, so the less ornate pointer spelling is retained.

The final bounds block uses the long-lived `ESI` position pointer for X but
tests Y as `player+0x18` through `EDI` at `0x004175ed`, then advances `EDI` to
that field for the remaining stores. Expressing the Y clamps through the
player record rather than the position alias recovers that source distinction
and raises the combined score to `51.73%`. A short-lived Y pointer compiles
identically; the direct field spelling remains the simplest plausible source.

The low-health direction at `0x004137b5..0x004137df` applies the `-6.0f`
scale to each wide `fcos`/`fsin` result before its first float store. Keeping
each trig call and scale in one ordinary assignment removes two premature
candidate stores, aligns one additional reference, and raises the current
score from `51.73%` to `51.77%`. An inlined vector `operator+=` for the
subsequent translation compiles identically, so the direct component adds are
retained as the simpler equivalent source.

Two stronger-looking alternatives were measured and rejected. Copying the
entry position as one aggregate lowers the score to `51.41%` and loses two
reference alignments. Giving Shrinkifier and Pistol separate scoped first-
sprite position/velocity values does preserve both native callsites, but grows
the frame to `0x50` and regresses the whole function to `50.87%`; the current
honest shared-local residual is kept instead.

The native reload preload gate at `0x00415037..0x00415069` first tests
`reload_timer - frame_dt < 0`, then tests `reload_timer > 0`. It never reads
the adjacent reload-active byte. Using the strict positive bound in the
scratch recovers the native second comparison and raises the whole-function
score from `39.10%` to `39.13%`. Both ports likewise key the preload only from
the positive timer crossing, including when a stale reload-active byte is
clear.

Angry Reloader writes the bonus-spawn guard to one at `0x00415132`, emits its
Plasma Minigun ring, and writes zero at `0x004151ce` before playing the impact
sound. The second store is unconditional; it does not restore the incoming
guard. Both ports now preserve that literal transition, with the Zig regression
starting from a set guard so a restore cannot pass accidentally.

The low-health pulse at `0x00413795..0x00413830` constructs its blood offset
in explicit vector phases: evaluate the heading-relative cosine and sine,
scale both components by `-6.0`, then translate them by the player's position.
It reloads `aim_heading` for the second trigonometric expression and only
captures the value used by the three effect calls after the translation.
Representing those natural value lifetimes recovers eight candidate
instructions and six additional reference matches, raising the whole-function
score from `38.72%` to `39.10%`. A temporary aggregate/constructor form grew
the stack frame, while combining scale and translation let VC6 reassociate the
arithmetic; neither reflects the observed native staging and both scored lower.

The native entry copies the adjacent `ui_mouse_x`/`ui_mouse_y` pair into the
selected two-float aim-screen slot with two integer moves. Representing both
pairs as the already-recovered local vector aggregate preserves that source
shape without bit-casting the individual floats merely to steer codegen.

Live disassembly also shows each early perk timer testing the perk count and
branching a zero result to its reset store, leaving the active update as the
fallthrough: Man Bomb at `0x004138bf`, Living Fortress at `0x004139c3`, Fire
Cough at `0x00413a0b`, and Hot Tempered at `0x00413c8a`. Restoring that natural
active-first source order changes no gameplay semantics, but recovers the
native `ebx`/`esi`/`edi` prologue through seven normalized instructions and
improves both whole-function alignment and reference recovery.

Live Binary Ninja shows the movement dispatcher at
`0x00413f19..0x00414f3e` laying out player-controlled modes first and branching
both demo mode and control mode `5` to the shared autoplay arm at
`0x00414c7f`. The earlier scratch put the demo arm first and left control mode
`5` stationary. Restoring the native condition and block order recovers the
computer-controlled movement behavior and raises the whole-function match from
`29.02%` to `37.79%`.

The same evidence revealed two rewrite-runtime parity defects. Aim scheme `5`
participates in the auto-target scan but does not select autoplay movement;
only demo mode or movement mode `5` does. The rewrite previously coupled
computer aim to computer movement. Also, the no-live-target arm at
`0x00414c7f` derives a tangential heading from the vector away from `(512,
512)`, so it orbits the arena rather than returning to center. The local input
interpreter now preserves the configured movement mode for computer aim and
reproduces that no-target orbit for computer movement.

The Zig rewrite had retained both defects independently in its local-input and
movement-runtime layers. It now routes autoplay only for demo mode or movement
mode `5`, preserves the configured movement vector when only aim scheme `5` is
selected, uses the native no-target tangent, and applies the zero deadzone used
by demo and point-click movement. Active port regressions cover each dispatcher
edge rather than relying on dormant module-local tests.

The firing dispatcher now follows the same native branch layout: an active Fire
Bullets timer falls through to the replacement path at `0x00415d13`, while an
inactive timer branches to the normal weapon cases at `0x00415eb8`. Man Bomb's
even and odd projectile arms each evaluate their randomized angle before
tail-merging at the common spawn, reproducing both native RNG call sites. The
Ammunition Within damage choice likewise converges on the single native
`player_take_damage` call instead of emitting one call per damage value.

Five native friendly-fire owner selections at `0x004138ea`, `0x00413a36`,
`0x00413cb5`, `0x0041512c`, and `0x00415be8` leave the enabled calculation
(`-1 - render_overlay_player_index`) in the fallthrough and branch to the
disabled sentinel (`-100`). The scratch now preserves that repeated natural
source order. The spread-damping gate at `0x00413d66` similarly leaves its
positive subtract-and-clamp arm in the fallthrough and branches to the
add-and-clamp arm. These source-level reversals recover six native references
without changing the instruction count or stack frame.

The spread-damping block is also active simulation state, not inert rendering
glue. Live instructions `0x00413d66..0x00413dcf` round the positive-gate
subtraction and the non-positive `frame_dt * 0.8f` recovery path at x87 PC=24,
then clamp the shared scalar to `[0.3, 1.0]`. The sole caller at `0x0040ad74`
loops `player_update` over every configured player, so the global advances once
for each live player. The Zig runtime previously declared both globals without
advancing them; its per-player perk phase now performs the native update after
Hot Tempered, matching both arithmetic staging and call cadence.

The two alternating projectile rings now also reproduce their native argument
selection. Man Bomb at `0x00413917` falls through on odd indices to the Ion
Rifle arm and branches on even indices to Ion Minigun, keeping the two native
random-angle evaluations. Hot Tempered at `0x00413ce1` selects Plasma Rifle or
Plasma Minigun directly in the call argument, which makes VC6 emit the native
`push owner; test parity; push type; shared call` sequence instead of reducing
a temporary projectile type arithmetically. Together with the owner and spread
ordering, this raises the whole-function score from `38.19%` to `38.72%`.

Live Binary Ninja isolates the native demo movement phase at
`0x00414c7f..0x00414f3e`. With no live target it derives an orbiting heading
from the vector away from `(512, 512)`. With a live target it pursues that
target while the player is within 300 units of center, otherwise steering back
toward center. Both cases reuse the normal heading approach, Long Distance
Runner acceleration, minigun speed cap, movement scaling, spawn avoidance, and
move-phase update. The recovered control flow places this as the demo arm of
the movement dispatch, so it joins the shared post-movement path without a
redundant demo-mode test.

This phase adds a net 164 candidate instructions against 186 native
instructions, closes the whole-function instruction gap from 591 to 427, and
raises the similarity ratio from `25.2142%` to `27.95%`. The Python demo driver
already implements the same orbit/pursuit/center-return policy, so no parity
port change is needed.

Live Binary Ninja isolates the native Fire Bullets path at
`0x00415d13..0x00415eb3`. The recovered source plays both dedicated shot
sounds, uses the fallback cooldown and muzzle-flash increment only when the
equipped weapon has one pellet, emits `pellet_count` type-`0x2d` projectiles
with `(rand() % 200 - 100) * 0.0015`, skips ammo consumption, spawns the gray
muzzle sprite, and adds the fallback spread term times `1.3` only without
Sharpshooter. It also corrects the normal path's first weapon heat increment:
native adds it to `muzzle_flash_alpha` (`player+0x2fc`), not `spread_heat`.

The new Fire Bullets block is 101 candidate instructions against 111 native
instructions and closes the whole-function instruction gap from 693 to 591.
The global similarity ratio nevertheless falls from `25.6510%` because the
corrected long-lived muzzle field and new branch perturb whole-function MSVC
register allocation and grow the candidate frame from `0x4c` to `0x54` while
native remains `0x48`. This is retained as substantive source recovery, not
represented as a matching-score improvement.

The accepted loop-family source follows the native weapon-case order and
restores 778 candidate instructions. Live Binary Ninja confirms the native
spread constants (`0.0013`, `0.004`, `0.002`, and `0.0026`), the Gauss/Ion
speed base of `1.4`, and the swarmer angular step of pi/3. The remaining
whole-function alignment delta comes from incomplete local-slot coalescing and
control paths. No register constraints or artificial padding are used.

## Port parity: Survival fire latch

Live instructions `0x0041590e..0x0041594f` first require either the normal or
reload-perk fire-ready byte, then require the configured fire key or auto-fire,
and only then write `1` to `survival_reward_fire_seen` at `0x00486fe4`. The
write precedes the Regression Bullets / Ammunition Within charge and actual
weapon dispatch. Both ports previously latched raw held fire during cooldown;
the weapon gate now owns the write, and replay input preprocessing no longer
manufactures it.

## Port parity: slot-zero perk ownership

Live Binary Ninja identifies 16 calls from `player_update` to the exact
`perk_count_get` helper, which always reads player slot 0. They cover Man Bomb,
Living Fortress, Fire Cough, Hot Tempered, Sharpshooter, Anxious Loader,
Stationary Reloader, Angry Reloader, Alternate Weapon, Regression Bullets, and
Ammunition Within. The recovered source also directly reads slot 0 for Long
Distance Runner, Fastshot, and the firing-path Sharpshooter check.

Both ports now select player 0 as the perk source for these phases when
`preserve_bugs` is enabled, while continuing to mutate the actual overlay
player's movement, timers, health, weapon, and projectile ownership. Corrected
mode retains intuitive per-player perk ownership. Focused co-op regressions
cover movement, a timed perk, and firing cooldown policy in both runtimes.

## Position type recovery

The player cursor is now carried as a `vec2f_t *` through every panned-audio
call instead of being shadowed by a raw `float *` alias. This exposes the
embedded position aggregate while preserving the honest 54.81% WIP score,
4,019/4,206 candidate/native instructions, and `736/0/11` reference audit.

Blood, vector-length, sprite, particle, and secondary-projectile calls now
carry the existing stack aggregates as complete vectors instead of repeatedly
taking their first float members. Particle movement is also recovered as a
read-only vector parameter. These source-only type improvements preserve the
same honest WIP score and reference audit.

The canonical `player_state_t` layout now exposes its four proven adjacent
float pairs as `vec2f_t` aggregates: world position at `+0x14`, movement at
`+0x1c`, aim at `+0x50`, and the click-to-move target at `+0x324`. Anonymous
scalar aliases preserve every existing field access and the `0x360` ABI.
`player_update` can consequently pass position and movement without interior
pointer casts, while the exact global constructor and near-exact gameplay
reset retain their native constructor lowering. The 4,206-instruction update
remains at `54.81%` with `736/0/11` references.

The position aggregate is now propagated through all remaining scratch
consumers: radius queries, demo/quest setup, perk and bonus effects, player
damage, overlays, projectile rendering, weapon assignment, and player reset.
Eight exact consumers retain byte identity; the larger render/perk/reset WIPs
retain their previous instruction counts, scores, and reference audits. Custom
C++ vector wrappers still reinterpret the named `position` object where their
operator lowering is required, but no consumer reconstructs it from
`&pos_x`.

The native weapon row is now represented by canonical
`weapon_storage_entry_t`: its ammo-class dword precedes the shifted public
`weapon_stats_t` view in each `0x7c`-byte row. Both player ammo-class tests
therefore use `weapon_ammo_class[player->weapon_id].ammo_class` instead of a
manual 31-dword stride. This is source-shape recovery only; validation remains
4,019/4,206 instructions at 54.8085% with `736/0/11` references.

All six direct projectile speed writes now use the flat
`projectile_t::fields.speed_scale` view. The nested `pos.tail.vy` overlay
remains available only where an evidenced interior pointer is needed to
reproduce native induction. This removes matching-layout plumbing from the
weapon cases without changing the 4,019/4,206 instruction count, 54.81% score,
or `736/0/11` reference audit.

The remaining direct aim and point-control target fields now use the canonical
`player_state_t::aim` and `player_state_t::move_target` aggregates. VC6 emits
the same 4,019/4,206 instructions, 54.86% score, seven-instruction prefix, and
`736/0/11` reference audit, so the stronger types do not steer the unresolved
whole-function allocation.

The Fire Cough smoke template now writes its two size components through
`effect_template_t::half_extent`, completing the already-recovered velocity
and color aggregate boundary. This is byte-neutral at the same 4,019/4,206
instructions, 54.86%, and `736/0/11` references.

## Function-local declaration-order sweep

The mutation harness tested all 12 declaration-order variants for the function-local temporaries. Every variant was byte-identical to the 56.6776% baseline (4023/4206 instructions, 7042.92-byte gap, five reference mismatches, `frame_size=0x48`). This rules out source declaration order as the control for the remaining stack layout: MSVC is placing these locals from their use sites instead. Recorded spec SHA: `91c82101299a1999c03ad3122f331f43cce50e5038264ce84faf892790180314`.

## Fire Cough scoped selected-player lifetime

The starting canonical build was 4,023/4,206 instructions at
`56.6776035970%`: 9,214.078 weighted bytes, a 7,042.922-byte fuzzy gap,
seven prefix instructions, and `766/0/5` reference results. A fresh compiler
profile check found VC6.0, VC6.5, and VC6.6 exactly identical. VC6.5pp
regressed to `48.2492211838%` and VC7.0 to `35.1396576136%`, so the retained
VC6.5 profile remains native-supported rather than being changed to chase a
score.

Live Binary Ninja shows a distinct selected-player lifetime in the native Fire
Cough block. The long-lived player in `EDI` supplies `aim_heading` at
`0x00413a88`, but the code reloads `render_overlay_player_index` at
`0x00413a8e` and constructs another player base in `EBP`. That reselected
player supplies aim at `0x00413aba` and `0x00413ac0`, position through `EBX`
at `0x00413aca`, and spread heat at `0x00413b4b`. The source now represents
that lifetime as a scoped `fire_player` pointer and uses it for aim, position,
and spread heat. This preserves the selected overlay player and does not add
codegen-only state.

An exhaustive 23/23 bounded mutation sweep covered direct versus scoped
reselection, three `vec2_sub` receiver/return shapes, projectile-position
reuse, and every interaction through three changed sites. Only the scoped
reselected player won. It improves weighted similarity by
`+90.3298187331` bytes and ratio by `+0.5556364565` percentage points while
removing ten candidate instructions and improving references by 12 exact and
two fewer mismatches. The retained build is 4,013/4,206 instructions at
`57.2332400535%`: 9,304.408 weighted bytes, a 6,952.592-byte fuzzy gap,
seven prefix instructions, and `778/0/3` references. The winner was separately
confirmed from source SHA
`386c42723d0264983766c8e88f97ad950703d9334911dcd29aad6287cb4e80cc`;
the sweep spec SHA is
`f552221b634c9e637751732b268898fa2760f6ad6f19208bc07ae6b19dd148c8`.

The negative cases are recorded rather than retained. Projectile-position
reuse lost 2.765 weighted bytes; reindexing only the `vec2_sub` receiver lost
4.477; retaining its returned receiver lost 126.437 and shortened the prefix
from seven instructions to two; direct unscoped reselection lost 161.098.
The closest interaction was scoped reselection plus receiver-return and
projectile reuse at `+90.3173151046`, still 0.0125 weighted bytes below the
single scoped-pointer change. Binding the selected player at two earlier
native-plausible points was byte-neutral in a complete 2/2 sweep (spec SHA
`1d5991be05806bbdb1e0243b73a9ee9015c03b82aac13a9ad1cb50e44da8d6b7`).

A corrected 6/6 source-shape sweep found pointer, const-pointer, reference,
and const-reference forms byte-identical. Copying aim as an aggregate lost
76.286 weighted bytes and one reference match; a named aggregate copy lost
228.802, shortened the prefix to one instruction, and raised reference
mismatches from three to six. Its authoritative spec SHA is
`a5d8c52b01a079819c17bee8b2c8e2c53ee995a757f516b70b3b84f8b7def6cf`.
The append-only experiment log also contains an earlier shape-plan SHA
`a1c5028e94173d2a149480090cc69f7c8f7b3a0180f038d46e6ff723f27b8ac3`
whose three reference cases were malformed by an unreplaced later `->`
access; those compile failures are not treated as negative match evidence.

The first mismatch remains the normalized branch target at native
`0x004136bf`, where the target jumps to its distant shared epilogue. The next
genuine scheduling difference is at function entry: native snapshots position
x/y before its health `fld`/`fcomp`, while VC6 schedules the health comparison
before completing those stores. The prior complete entry-snapshot and
declaration-order sweeps ruled out the ordinary source forms tested there, so
this Fire Cough improvement is retained without claiming that the remaining
6,952.592-byte compiler residual is solved.

## Main firing spread-angle lifetime

The next live reference audit found three mismatches. At `0x00413eb2`, native
keeps the 384-creature scan cursor at the `creature_pool` record base while
VC6 rewrites the recovered pointer to `creature_pool + 0x18`; at
`0x0041419e`, native's movement-mode tail loads
`render_overlay_player_index` where the aligned candidate has already entered
the next mode and loads `grim_interface_ptr`; and at `0x00415c78`, native's
spread-angle constant was aligned with the candidate's later spread multiplier.
The last mismatch identified a recoverable local lifetime rather than a wrong
constant.

Native calls `crt_rand` for the main spread angle at `0x00415c66`, converts
and multiplies it by `0.012271847f`, then stores it in its own stack slot at
`0x00415c7e`. The recovered source had instead borrowed `scratch_pos.x` for
that value even though the later weapon dispatcher initializes every
`scratch_pos` component before reading it. Giving the angle its own ordinary
`float spread_angle` local is behavior-preserving and exposes the native
lifetime. It improves weighted similarity by `+755.5875410634` bytes, raises
the ratio by 4.6477673683 percentage points, adds 12 exact references, removes
the spread reference mismatch, and leaves the candidate at 4,013 instructions.
The 6/6 recorded sweep spec SHA is
`1a7d5ed9bbae337089bdf643b8b94e8ecee8137388cb5f63c234d676b1268891`.

The native follow-up sequence at `0x00415c98..0x00415ca8` first converts the
second random value, then loads the saved radius, multiplies it by spread heat,
combines the two x87 values with `fmulp`, and finally multiplies by
`0.001953125f`. Grouping the source as random times `(radius * spread_heat)`
recovers that same candidate sequence at object offsets `0x2390..0x23a2`.
This adds one native-shaped instruction and another `+2.7316307328` weighted
bytes without changing references. The complete 6/6 follow-up spec SHA is
`fc1dd715bcbfb19101af5c26960616d0fd99c6036bb2b1fb1f72125ec7936159`.

Across this slice the canonical build moves from 4,013/4,206 instructions at
`57.2332400535%`, 9,304.408 weighted bytes, a 6,952.592-byte gap, and
`778/0/3` references to 4,014/4,206 at `61.8978102190%`, 10,062.727 weighted
bytes, a 6,194.273-byte gap, and `790/0/2` references. The prefix remains seven
instructions. Final source SHA is
`6f3eb8ad7f0d1b6c5ea0ab826e8f0c6fd61b52594abe6a0198e8fffba50ea678`.

The bounded negatives are also recorded. Eight creature-loop variants found
only a 5.089-byte gain from direct indexing, but it added a fourth reference
mismatch and contradicted native's base-pointer induction, so it was rejected;
three indexed pointer/reference forms lost 11.868 bytes and all ordinary
pointer spellings were neutral (spec SHA
`f4dc4ce635173d5a7f38307b3aa7912f5882541ed0a354117e71411d6128cf29`).
Six active-condition and end-pointer spellings were byte-neutral (spec SHA
`96f14f42e57d327e415b26650df327faa0faf1d04d7e616e064407cab21fad88`).
Main-firing selected-player reselection gained only 1.119 bytes before the
angle recovery while adding six instructions; after the angle recovery it
lost 11.292 bytes, or 8.561 with native product grouping, so it was not
retained (initial spec SHA
`bd0ed66a4c9eaff4d9d7e79e51673ac3ee53f467a6cd667a5e83a83bfc11bcd7`).
Naming only the radius was byte-neutral; naming both radius and angle,
aggregate product variants, and scoped-player interactions all trailed the
angle-only winner. `const`, split initialization, and an explicit random
integer were byte-neutral.

The final two audit mismatches are therefore documented compiler/alignment
residuals: the creature scan's field-anchored induction pointer and the
movement-mode tail alignment. No unsupported compiler profile, artificial
dependency, volatile access, register constraint, or layout-only control flow
is retained.

## Movement vector frame snapshots

The starting build for this slice was 4,014/4,206 instructions at
`61.8978102189781%`: 10,062.727007299270 weighted bytes, a
6,194.272992700729-byte gap, a seven-instruction prefix, and `790/0/2`
references. Its source SHA-256 was
`6f3eb8ad7f0d1b6c5ea0ab826e8f0c6fd61b52594abe6a0198e8fffba50ea678`.

The highest-weight remaining region, native
`0x004168c2..0x00416b4c`, covers Multi Plasma and the following direct
projectile cases. Live instructions show a repeated stack position at
`+0x48/+0x4c`, but the apparent source-level explanations were false leads.
An exhaustive 255/255 sweep replacing eight branch-local positions with the
existing shared vector was completely byte-neutral (spec SHA
`a2169e235b7d8b8e684dc3df1e89010a5618f5eed34f670e7c6d71c6a7322aae`).
The 9/9 Y-before-X sweep had no winner and regressed eight cases by
31.644--106.798 weighted bytes (spec SHA
`02bc26cd203b983ba8939aca9753c6aba08cf8fe6b1aeb2cbcc4fccdc61983c2`);
eight aggregate initializers were byte-neutral in the expanded 17/17 plan
(spec SHA
`269114a5a16f279bb13f0416369ccf6997cd3eb8ec94cff740a3d4a6c89ac92c`).
A distinct projectile-position object lost 119.971 weighted bytes at function
scope and 1,042.944 bytes at firing-block scope, both shortening the prefix
from seven instructions to one. Moving the recovered spread-angle declaration
to function scope lost another 59.332 bytes. None of those layout explanations
is retained.

The next high-impact region, native `0x00414805..0x00414ac4`, exposed an
ordinary missing value lifetime. Native movement tails load `frame_dt` once,
duplicate it on x87, and use the same value for both movement components. The
mode-3 idle tail does this at `0x004143f2..0x0041440c`; all three mode-1
tails do it independently at `0x00414624..0x00414676`,
`0x004146f1..0x0041474b`, and `0x004147e6..0x00414834`; and the mode-2
paths repeat the pattern before their shared call at `0x00414c57`. The
starting candidate instead reloaded the global separately, for example at
object offsets `0x00000fef` and `0x00001008`.

The retained source snapshots `frame_dt` into an ordinary block-local
`const float movement_dt` before scaling the two components in the mode-3
idle arm, mode-1 idle arm, and common mode-2 tail. They preserve runtime
semantics while preventing VC6 from collapsing native-distinct arm bodies.
The final object contains the recovered single-load/duplicate shapes at
candidate offsets `0x00000c74`, `0x00000f9b`, and `0x0000147c`.

The first mutation plan evaluated all 8/8 one-site variants and all 80/80
interactions through four sites (spec SHA
`2d1dd185e285fc999bbceaf7391260b2b56d886a4de17bbac287e83cc45ab282`).
A second add/remove plan exhaustively evaluated all 31/31 combinations around
the stronger retained state and found no improvement (spec SHA
`e28f633901b03bede6691893a5edc2dbcfe3aff928905045b3fdec48ab01fdbc`).
Removing the mode-3 snapshot lost 43.665 weighted bytes and five references;
removing the mode-1 idle snapshot lost 27.363 bytes, 13 instructions, and four
references; removing the mode-2 snapshot lost 3.938 bytes. The mode-1
backward snapshot was byte-neutral and was removed. Applying snapshots to all
ten movement-vector sites lost 1.224 weighted bytes, so the unsupported broad
form is recorded but not retained.

The canonical build now has 4,051/4,206 instructions at
`62.4924306648904%`: 10,159.394453191231 weighted bytes, a
6,097.605546808769-byte gap, the same seven-instruction prefix, and
`800/0/2` references. This is a gain of 96.667445891961 weighted bytes and
0.594620445912 percentage points. A recorded zero-delta confirmation uses
source SHA
`3e91e771c50e0571c354b6ccb8f217298feeafeff766c9afe6a2c9e6d0d6254d`.

The two audit mismatches are unchanged and remain rejected residuals. At
native `0x00413eb2` / candidate offset 2001, native references the
`creature_pool` record base while VC6 anchors the cursor at
`creature_pool+0x18`. At native `0x0041419e` / candidate offset 2748, the
aligned target load of `render_overlay_player_index` is paired with the
candidate's later `grim_interface_ptr` load. The final audit is otherwise
`800/0/2`; no unsupported layout trick was used to hide either mismatch.

## Alternate Weapon swap orientation

The starting build for this slice was 4,051/4,206 instructions at
`62.4924306648904%`: 10,159.394453191231 weighted bytes, a
6,097.605546808769-byte gap, a seven-instruction prefix, and `800/0/2`
references.

Live Binary Ninja instructions `0x00415813..0x00415831` expose the source
orientation of Alternate Weapon's integer swap. Native first loads the current
`weapon_id`, then loads `alt_weapon_id`, stores the current value to the
alternate field, and finally stores the alternate value through a materialized
pointer to the current field. This is the ordinary
`temporary = current; current = alternate; alternate = temporary` spelling.
The recovered source used the behaviorally equivalent opposite orientation.

The exhaustive seven-field interaction plan
`alternate-weapon-swap-orientation-mutations.json` evaluated all `127/127`
subsets through seven changes, with no unevaluated combinations (spec SHA-256
`ffda5271ae1d76082679aea559507a7540fb7f5499af0b53a1ea89318b5b2a14`).
Only reversing the integer `weapon_id` swap changes codegen; reversing any
combination of the six float/byte swaps is byte-neutral. The single-site
winner follows the native load/store order and improves weighted similarity by
`+3.937749788058` bytes and the ratio by `+0.024221872351` percentage
points. It leaves instruction coverage, prefix, and reference audit unchanged.

The canonical build is now 4,051/4,206 instructions at
`62.5166525372411%`: 10,163.332202979289 weighted bytes, a
6,093.667797020711-byte gap, a seven-instruction prefix, and `800/0/2`
references. A recorded zero-delta confirmation uses source SHA-256
`685f369f91ee9cddfdf5ea212a4e00035dee3de95b9665cb8a2f8a492e281971`.

Four additional BN-guided source families were measured and rejected. The
long-lived muzzle-flash pointer declaration/initialization plan evaluated all
`9/9` variants and found only byte-neutral valid forms (spec SHA-256
`857fe636c1acb8f5c727f6362bb6b25af7e0143f637d35cb28a6e98a35865c15`).
The low-health blood-vector plan evaluated all `4/4` forms; grouping both
translations gained `4.923976470711` aggregate weighted bytes, but it emitted
the opposite local x87 lifetime from native `0x00413795..0x004137ed`, removed
four candidate instructions, and worsened references from `800/0/2` to
`798/0/4`, so it was not retained (spec SHA-256
`78b6a908fe68fa600d69c65a3d43a65c48e8c8d1b320b8d9a6d077cbb41ab1f4`).
Five scalar-X lifetime forms all lost `43.577637102062` weighted bytes and
eight reference matches (spec SHA-256
`749780a737fed0cae22145ee2ad1f21be973b2baf9ba4212073402a284d4861b`).
Finally, an inlined vector-operator probe over the Plasma Rifle and
Multi-Plasma position expressions evaluated all `15/15` variants; unused
operator definitions were neutral and every used form regressed (spec SHA-256
`d1f6430b1f8534f312e8bd9a59e00617ff834145d164fe7b9d029e9f40a09b06`).
These negative records rule out the tempting pointer, x87-expression, and
return-by-value explanations without weakening the native-supported source.

## Entry-health scheduling and movement-heading precision

The first substantive entry divergence remains the scheduling around
`0x004136f3..0x0041370b`: native stores both previous-position components
before comparing health, while VC6 schedules the equivalent x87 comparison
through those stores. `entry-health-lifetime-mutations.json` exhaustively
tested six short-lived float, split-float, pointer, const-pointer, and
const-reference spellings. All six variants were byte-identical, so none was
retained. The recorded spec SHA-256 is
`98c5de36f61acf8d175399e1294a48368e4b86be1556fb185b10e6957595d4b8`.

A later BN-guided check found one genuine source-precision error inside the
large movement region. Native `0x004149ba` stores float bits `0x40afede0`
(`5.4977874755859375`) for the diagonal heading, while the former
`5.497787f` spelling compiled to `0x40afeddf`. The
`movement-heading-precision-mutations.json` sweep tested three exact-rounding
source spellings (spec SHA-256
`8e638044008c27dfdc2d837757a7d0f070ac3253c4b68e3d69ca895aadce0002`);
`5.4977875f` is retained because an object dump confirms that it emits the
native `0x40afede0` immediate. Python, Zig, and their parity tests already use
the same exact binary32 value.

This one-byte correction lies inside an already structurally mismatched
region, so aggregate fuzzy metrics are unchanged: 4,051/4,206 instructions,
`62.5166525372411%`, 10,163.332202979289 weighted bytes, a
6,093.667797020711-byte gap, prefix 7, and `800/0/2` references. No
score-only source change was retained. The final source SHA-256 is
`511f6e20a5f868e673511573252e1676416a3ca69f2884132d0e872cb5278929`;
the 38-record `experiments.jsonl` SHA-256 is
`727aa640c532445e4559235d1884d3791087f3421d99242d4d12840002579923`.
