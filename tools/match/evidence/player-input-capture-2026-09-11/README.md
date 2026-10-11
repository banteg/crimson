# Preserve native query ownership and accepted firing intent

The Frida capture agent this package repaired, its Python finalizer and the
Zig port have since been removed. The native findings stand; the capture and
transport sections are a historical record.

The capture agent had three input errors:

- A Grim query filtered out by `onEnter` still popped the thread's context stack
  in `onLeave`. `grim_is_key_active` calls `grim_is_key_down` for keyboard input,
  so the nested call consumed its parent context. Filtered Grim calls inside a
  primary-input helper could also consume that helper's context and lose its
  result entirely. Each Grim invocation now records whether it owns an entry.
- Byte-returning methods were read as full EAX values. The original
  `input_primary_just_pressed` returns false with `xor al, al` at `0x004460e8`;
  `input_any_key_pressed` tests AL at `0x00446015` and retains the last false
  result on return. Nonzero upper bytes do not mean pressed. These methods and
  both Grim query methods now use AL; the integer `input_primary_is_down` method
  retains its full-width result.
- Computer aim can fire while the physical fire key is released. The capture
  now records effective `fire_down` when the fixed G query returns to
  `0x00415cee`, after the native shot gates and perk costs. The owner is read
  from `render_overlay_player_index` at `0x004aaf0c`; an invalid owner makes the
  capture fail. The query result independently determines held G input.

The accepted-shot marker checks the exact method, scan code, and callsite. A
G query elsewhere, or a perk-created projectile, cannot synthesize weapon fire.
The G shortcut remains restricted to `preserve_bugs` in both ports.

## Native and callback evidence

A native verifier executed 48 original `player_update` cases and the then-current
compiled C++ body. All observed state bytes and ordered modeled calls agree; the first
38 native observation hashes also agree with the existing G-shortcut proof.
The additional cases cover computer fire without G, distant aim, cooldown, and
Man Bomb / Hot Tempered projectile creation for both player indices.

The runner recorded each native key query's return address. A Node harness fed
those events through the then-production Frida callbacks, player-key state updates,
replay-intent builder, and packed input encoder. It models the native keyboard
method's nested call to `grim_is_key_down` (return address `0x100071a2`).

The captured packets drive the Python firing routine for 42 applicable cases;
all firing/timer checks agree with the original. The two console cases remain
native/capture witnesses because the port pauses outside this routine. The
four perk-only cases each create eight native projectiles and capture no weapon
fire. They do not serve as port perk-equivalence checks.

The saved old callback block fails four port comparisons: computer auto-fire
for each player, with and without G. The same native inputs pass with the new
callbacks. No physical-fire-key value is invented for these witnesses.

Eight additional original-machine-code controls exercise byte-returning input
helpers. Six return false in AL with nonzero upper EAX bits; the old callbacks
misread all six as pressed, while the current callbacks decode all eight
correctly. The `input_any_key_pressed` boundary model supplies false in AL for
all 381 queried keys. The console-open primary-helper controls execute without
external callbacks.

A control script also ran seven callback controls against both bodies.
The old body fails nested primary ownership, tracked/interleaved ownership,
byte decoding, and both selected auto-fire controls. Both unchanged controls
pass: full-width integer returns and an unrelated query with projectile counts.
The current body passes all seven. The larger pytest matrix also checks both
G values, invalid owners, later false physical queries, and callsite isolation.

The old callback block is the exact input-hook block from commit `744be669f`,
SHA-256 `ba1cf2f034135e8b561dd03fd214d42f679d52439619cae8df9701088271333f`.
The negative control uses the current surrounding capture helpers with that
old callback block; the new firing helper is unused by the old block.

## Replay transport

A port-side verifier recorded eight two-player CRDs from the four auto-fire capture
witnesses, each using old or current packets. A neutral second let the normal
reset cooldown expire, followed by one captured packet and released input.
All 640 complete Python/Zig ticks agreed on every canonical trace channel.

Old packets produced no shots. Current packets produced one shot from the
intended player. G granted the timer only to that player; without G the timer
stayed zero. Per-player shot counters are checked separately from replay claimed
stats, which describe player zero. This tests transport and playback from the
normal reset state; it is not a native whole-frame simulation comparison.

`results.json`, `controls.json`, and `port-results.json` pin the original image,
runner, current/saved callback sources, fixtures, compiled candidate, tested
Zig binary, CRDs, and trace comparisons. Generated full capture inputs are
written to the requested output directory. The C++ source is compiled in that
private directory so this proof does not overwrite canonical match objects.

The shared native runner executes original movement, heading, vector, and CRT
conversion helpers. Input, RNG, allocation, effects, damage, reload, and sound
boundaries are explicit models. The Node harness modeled Frida dispatch, memory
reads, and event sinks; no live injected-game capture is claimed here.

## Format and reproduction

Raw capture and producer version advanced to 28 so old captures could not
silently retain the former input semantics. CRD 19, CDT container 2 / schema 19,
checkpoint 5, and evidence sidecar 3 retained their layouts. Agent, Python
finalizer, Zig verifier, and format documentation agreed on the then-current
tuple.

The verifiers, callback controls and Node harness read the removed
`scripts/frida/gameplay_diff_capture.js`, and the port check also needed the
removed Zig binary, so they were removed with that tooling; the receipts are
the record. The
G-key policy remains covered by `tests/gameplay/test_fire_bullets_shortcut.py`.
This slice changed capture tooling and its version agreement; it retains the
existing C++ body and makes no new exact-match claim.

Validation also passed 293 related Python tests (one imported-capture fixture
skip), all 732 Zig tests, the native ReleaseFast build, and the existing
256-tick G-policy replay matrix. Ruff, type checks, import contracts, docs,
structural rules/tests, current format checks, native closure, strict experiment
validation, and matching regressions passed. The report's function evidence is
unchanged; its repository-input hashes are refreshed.
