# Violence-disabled branch audit

The missing Python low-health argument caused the blood helper to receive
`violence_disabled=0` in every run. `WorldState.step` now passes the run setting
through `player_update`. Zig already passed that setting to low-health blood;
its perk menu and quest-unlock text now also use the active session setting,
including command-line overrides.

Low health still resets its timer and plays the warning sound with gore
disabled. It suppresses the six blood particles and their thirty RNG draws.
The warning consumes one draw for sound selection in either mode. This is
native behavior, independent of the ports' preserve-bugs setting.

## Native flag inventory

[verify.py](verify.py) scans the complete native function manifest for accesses
to `config_violence_disabled` at `0x004807b4` (`config_blob + 0x46c`). The scan
finds **eight reads in seven functions**, plus three direct writes. All seven
readers have corresponding port behavior:

| Native reader | Behavior when the flag is nonzero | Port implementation |
| --- | --- | --- |
| `creature_render_type` | Draw doubled additive white hit flashes after each species' body batch. | [Hit-flash proof](../creature-hit-flash-2026-09-11/README.md); Python and Zig renderers. |
| `projectile_update` | Suppress blood production, retaining RNG outside the guarded block. | Python `presentation_step.py`; Zig `projectiles.zig`; [impact proof](../primary-impact-presentation-2026-09-11/README.md). |
| `creature_update_all` (two reads) | Suppress corpse decals and the ping-pong corpse's blood burst. | Python `CreaturePool._tick_dead`; Zig `tickDead`. |
| `fx_queue_add_random` | Return before choosing a random blood decal. | Python `FxQueue.add_random`; Zig `FxQueue.addRandom`. |
| `effect_spawn_blood_splatter` | Return before touching the effect template or RNG. | Python and Zig blood-splatter helpers, including the corrected low-health caller. |
| `perks_init_database` | Give perk 1 its Quick Learner name and description. | Python and Zig perk display functions. |
| `options_menu_update` | Refresh the same perk text after configuration changes. | Port display functions resolve the current setting when rendering text. |

The three direct writes belong to default initialization, configuration reload,
and missing-file creation. Native missing-file creation writes `1`; the ports'
modern configuration initialization defaults to `0`. Both codecs store and
load the byte. This audit does not recreate Grim2D's Windows parental-password
dialogs or change the modern default.

The scan also reports register-relative operands with displacement `0x46c`
and literal pointers to the flag. Its sole displacement candidate is a local
stack write in `config_sync_from_grim`, not another gameplay reader. There are
no literal pointers to the flag. This is an instruction-reference inventory;
it is not a proof against every possible dynamically computed alias.

## Low-health execution evidence

The original `player_update` and `effect_spawn_blood_splatter` bodies execute
under the existing guarded player runner. The current C++ `player_update`
executes with that same original blood helper. Complete observed state,
ordered calls, and non-stack writes agree for **192 cases**:

- Both selected player slots; zero and nonzero violence values (`0`, `1`, `255`).
- Dead players, low health, the float immediately below 20, and exactly 20.
- The `100` timer sentinel, expired timers, positive timers crossing zero,
  and timers reaching exactly zero, at two positive frame durations.

Slot 1 remains a direct selected-slot diagnostic in the shared runner, whose
configured player count is one. A separate Python world-step regression
exercises two live low-health players and checks propagation to both.

A deliberately dropped flag must reproduce six unwanted allocations and
31 RNG draws instead of zero allocations and one draw. That negative control
is detected. [results.json](results.json) records the inventory, control,
source and image identities, and per-case observation hashes.

The shared [fixture](../../../../crimson-zig/src/runtime/testdata/violence-disabled-low-health.json)
checks actual Python player updates and Zig player preprocessing against
native timer bits, effect count, position, written template fields, sound
selection, and final RNG state. Python additionally compares all RNG values
and sound position/gain. Template `scale` is excluded: this helper preserves
that field, while the runner starts its template at zero. Zig's runtime sound
buffer retains sample IDs rather than spatial/gain data, so it does not check
those sound fields.

Allocation, sound, input, and RNG remain explicit callback models; no audio
backend or GPU executes in this proof. The C++ matching source is unchanged,
so this slice claims no newly matched function or byte.

## Reproduce

```sh
uv run --with unicorn==2.1.4 python \
  tools/match/evidence/violence-disabled-2026-09-11/verify.py \
  --out /tmp/crimson-violence-disabled
cmp /tmp/crimson-violence-disabled/witnesses.json \
  crimson-zig/src/runtime/testdata/violence-disabled-low-health.json
uv run pytest --no-cov tests/gameplay/test_low_health_violence_native.py
```

Run `zig build test --summary all` from `crimson-zig`. Unicorn execution on
macOS requires permission for JIT memory allocation.
