# Fixed G-key Fire Bullets shortcut

The supplied `1.9.93-gog` executable queries DIK_G (`0x22`) inside the eligible
shot path of `player_update`. A true result assigns `10.0f` to the firing
player's `fire_bullets_timer`; that same shot dispatches Fire Bullets.

Native instruction anchors:

- `0x00415ce8`: indirect `grim_is_key_active` call, with `0x22` already pushed.
- `0x00415cee`: test the returned byte.
- `0x00415cf2`: write `0x41200000` (`10.0f`) to `[edi+0x31c]`.
- `0x00415cfc`: reload the timer for the Fire Bullets branch.

The call follows the ready/input gates, the XP/health reload-bypass cost,
casing effects, and shot jitter. There is no developer-mode check on this path.
The recovered Grim method delegates scan codes at or below `0xff` to
`grim_is_key_down`. This looks like a leftover cheat hook; intent and other
executable versions are not established by this evidence.

## Native witnesses

`verify.py` runs 38 cases against original machine code and the current compiled
C++ body. All observed final state bytes and ordered modeled calls agree.
Fourteen cases assign ten seconds. The controls cover both player indices,
G-only/no-G inputs, cooldown, reload, death, console, empty ammo, refresh,
overwriting a longer timer, Regression Bullets, Ammunition Within with/without
XP, and computer auto-fire. The non-firing player's timer stays zero.

The shared [runner](../player-aim-direction-2026-09-11/runner.py) executes the
original movement, heading, vector, and CRT-conversion helpers. Input, RNG,
allocation, effects, damage, reload, and sound boundaries are explicit models.
Damage and reload callbacks are no-ops; the fixture checks their invocation and
ordering, not their internals. Weapon rows are synthetic fixed controls.
These are bounded routine witnesses, not a whole-executable equivalence proof.
Compiler-checked layouts, image/runner/engine hashes, candidate metrics, case
inputs, observation hashes, and ordered native calls are in `results.json`.

The previous C++ source already contained this shortcut. This slice corrects
the ports and records evidence; it makes no new exact-match claim.

## Port policy and playback

Normal play ignores the shortcut. `--preserve-bugs` enables it after the firing
gates and perk cost. The timer is assigned, not added or maximized. Existing
Fire Bullets pickups remain available in both modes.

Both local-input paths sample the fixed G scan code. `fire_bullets_key_down` is
held input, carried as packed bit 17 through CRD/CDT and native capture. Both
firing routines enforce `preserve_bugs`, so supplying the flag through replay
cannot grant the bonus in normal play. The ports decide the bonus before pure
shot setup/casing work; no port callback there reads the timer. The native call
and write happen after the jitter work described above.

The exported shared fixture is
`crimson-zig/src/runtime/testdata/player-fire-bullets-shortcut.json`.
Python and Zig tests check timer assignment, firing, current-shot projectile
type, ammo preservation, policy gating, and input decoding. Console-open cases
remain native witnesses: the port pauses the whole frame outside these weapon
unit tests. Live-input and Frida tests check the held key independently of the
configured firing binding; input-provider tests retain it through catch-up.

`verify_ports.py` records four fresh 64-tick CRDs with preserve-bugs and G each
on/off, including a release/re-hold interval. Python and Zig agree on every
canonical trace channel for all 256 ticks with no diagnostics. The three
non-cheat controls have identical gameplay-channel hashes, excluding the
intentional input flag difference. The enabled case ends with timer
`9.900001525878906`, two fired shots, and all ten rounds; the controls end with
zero timer, one fired shot, and nine rounds. `port-results.json` pins the
sources and tested Zig binary.

The current-only contract becomes CRD 19, CDT payload 19, and Frida raw 27.
CDT container 2, checkpoint 5, and evidence sidecar 3 retain their layouts.
Older recordings must be regenerated; there is no silent migration.

## Reproduce

```sh
uv run --with unicorn==2.1.4 python tools/match/evidence/player-fire-bullets-shortcut-2026-09-11/verify.py --out /tmp/fire-shortcut-native
cd crimson-zig
zig build -Doptimize=ReleaseFast
cd ..
uv run python tools/match/evidence/player-fire-bullets-shortcut-2026-09-11/verify_ports.py --out /tmp/fire-shortcut-ports
uv run pytest -q tests/gameplay/test_fire_bullets_shortcut.py tests/debug/test_fire_bullets_shortcut_capture.py tests/sim/test_input_provider_semantics.py
```

The native runner requires executable-memory support for Unicorn and the local
VC6/Wibo toolchain. A restricted macOS sandbox can terminate it with SIGILL.

## Validation

- Native routine: 38/38 original/current observations agree.
- Complete replay: 256/256 Python/Zig ticks agree on all six channels.
- Python: 3,669 passed, 13 skipped in the sandboxed full suite; the three
  display-dependent shader tests then passed with display access. Ten remaining
  skips concern opt-in terrain tests and absent imported replay/capture fixtures.
- Zig: 732 passed in Debug and ReleaseFast; native ReleaseFast and WebAssembly
  builds passed.
- Ruff, ty, import contracts, docs, ast-grep rules/tests, current format matrix,
  native closure, strict experiment validation, and match regressions passed.
- Matching artifacts remain current; no recovered C++ body changed in this slice.
