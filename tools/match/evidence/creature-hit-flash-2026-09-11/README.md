# Native creature hit flashes

Python and Zig now draw the native white hit-flash pass when violence is
disabled. Zig also tracks the timer through damage, active updates, replay
residue, and slot allocation. The previous Python renderer omitted the pass;
the previous Zig runtime had no timer field and its renderer omitted the pass.

The native effect draws each eligible sprite **twice with additive blending**
after its species' body batch. Its alpha is
`min(hit_flash_timer * 5, 1) * transition_alpha`, followed by Grim2D's truncated
byte packing. A dying long-strip shock creature omits the `+32` offset used by
its body. The flash preserves actual creature size, including sizes outside
the then-current Python body's clamp. Zig now uses the recovered species order
`zombie, spider_sp1, spider_sp2, alien, lizard` to place these batches correctly.

The timer is set to `0.2f` before native damage checks, including zero damage,
corpse hits, and direct calls on inactive valid slots. It decreases on active
slots even during Freeze and is allowed to cross zero. Allocation resets it;
the existing CRD slot-residue field restores it without a format change.

This corrects port behavior. The C++ matching sources are unchanged; no newly
matched function or byte is claimed. `creature_render_type` remains
79.737705%, 760/765 instructions, and `139/0/5` references.

## Evidence

[verify.py](verify.py) executes the original game and the current C++ objects
in private build directories, using the existing guarded renderer, update,
and primary-impact runners. Complete ordered calls and observed state/writes
agree in the tested scopes:

- **84 render cases:** six direct-rendered species, seven transition values,
  both violence settings, positive/zero/negative timers, corpse and alive
  frames, an inactive slot, and an entry of another species. The pass's two
  quads agree exactly, and destination blending is restored.
- **8 update cases / 88 timer observations:** four positive frame durations,
  frozen and unfrozen pools, inactive and active records, live and dead
  records, zero crossing, and the last slot.
- **480 damage cases:** five damage categories, zero and nonzero damage,
  live/dead health, ping-pong flags, first/last slots, active/inactive records,
  and empty/nonempty player lists. The inactive/empty cases are direct-call
  diagnostics, not a claim about their occurrence in ordinary gameplay.

The color observer executes the actual Grim2D color-pointer body. Its imported
`_ftol` is resolved to the game's unchanged native CRT converter as an explicit
ABI model; the external MSVCRT implementation is not loaded. Image hashes,
compiled creature-field offsets, runner identities, candidate body hashes,
call/write digests, and that import binding are recorded in
[results.json](results.json). Deliberately wrong fade, single-quad, and
inactive-damage-gate controls must be detected.

The shared [witness file](../../../../crimson-zig/src/runtime/testdata/creature-hit-flash.json)
drives Python and Zig lifetime/selection regressions. Python also intercepts
the production draw calls and checks frame, size, position, rotation, packed
alpha, duplicate quads, blend restoration, the violence gate, and per-species
flash placement. Zig checks the selection and packed-alpha helper used by its
window renderer. Both ports additionally check all **2,640** preexisting
native flash-frame witnesses. Zig's existing primary-impact regressions now
compare the native timer field too.

Python replay playback copies the recording's gore setting into its rendering
configuration. Two opposite-preference regressions check that both the replay
simulation and render frame use that setting while retaining the viewer's
saved preference.

This is a bounded CPU/call audit. It does not certify GPU pixels or the existing
shadow/body tint and geometry approximations. The later
[pass-order audit](../creature-pass-order-2026-09-11/README.md) corrects the
ports' shadow/body interleaving, Python size clamp and fixed atlas divisor.
Trooper cases exercise the direct type renderer; native `creature_render_all`
omits that species.

## Reproduce

```sh
uv run --with unicorn==2.1.4 python \
  tools/match/evidence/creature-hit-flash-2026-09-11/verify.py \
  --out /tmp/crimson-creature-hit-flash
cmp /tmp/crimson-creature-hit-flash/witnesses.json \
  crimson-zig/src/runtime/testdata/creature-hit-flash.json
uv run pytest --no-cov tests/creatures/test_creature_hit_flash.py \
  tests/creatures/test_creature_frame_native.py tests/render/test_world_draw_order.py
```

Run `zig build test --summary all` and
`zig build test -Doptimize=ReleaseFast --summary all` from `crimson-zig`.
Unicorn execution on macOS requires permission for JIT memory allocation.
