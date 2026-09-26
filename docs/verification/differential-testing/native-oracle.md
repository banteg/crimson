---
tags:
  - verification
  - differential-testing
  - float-parity
---

# Native execution oracle

`crimson.dbg.native_oracle` runs functions of the original `crimsonland.exe`
under Unicorn x86 emulation, so a port function can be checked bit for bit
against native code without a capture. Use it for float math, spawn stat
tables and other leaf or near-leaf gameplay code.

## How it works

- The PE is mapped at its preferred base `0x00400000` with section permissions.
  Writable `.data`/`.data1` start with their file contents, so globals hold
  their pre-startup values.
- Each call starts with `fninit` and control word `0x007F` (PC24,
  round-to-nearest). That is the precision Direct3D 8 leaves during gameplay; see
  [float parity policy](../../rewrite/float-parity-policy.md). Pass
  `control_word=` to override.
- Stack arguments follow cdecl/stdcall: Python `float` and `F32` push a
  float32, and `F64` pushes a double. `ecx=` covers thiscall. `st=` preloads the
  x87 stack for register-argument helpers such as `__ftol`. `CallResult` has
  `eax`, `edx`, the exact 80-bit x87 stack (`st0`) and `stack_popped` (the
  callee's `ret N`).
- `run(start, stop, regs=..., frame=...)` executes a code fragment of a larger
  function, for example the spawn block of `typo_gameplay_update_and_render`.
- `run_static_initializers()` runs the CRT `__xi` and `__xc` tables. This
  applies C++ defaults such as the weapon-table travel budgets. The CRT
  stdio and locale initializers trap and are skipped.
- The CRT runs natively. `TlsGetValue` returns a fake `_tiddata`, so `crt_rand`
  works, and `oracle.rand_state` reads or writes its `_holdrand`. Win32 heap
  calls come from a scratch heap, and critical sections are no-ops. An FS
  segment points at a fake TIB, so SEH prologues (`fs:[0]`) work.
- Any access to unmapped memory, write to read-only memory, jump through an
  unset pointer or call of an import without a stub raises `NativeTrap`. The
  message names the address, the instruction, the registers and the nearest
  symbol from `analysis/ghidra/maps`. That tells you which global to seed or
  which callee to stub.
- `stub(name_or_address, fn_or_constant, pop=, returns="eax"|"st0")` replaces
  a native function with a Python callback. `stub_import(name, ...)` answers an
  import. `trace_memory()` records the globals that native code reads and
  writes. `snapshot()` and `restore()` reset state between cases.

```python
from crimson.dbg.native_oracle import NativeOracle

oracle = NativeOracle()
oracle.run_static_initializers()
angle = oracle.alloc_f32s(1.0)
oracle.write_f32("frame_dt", 0.016)
oracle.call("angle_approach", angle, 2.0, 3.0)  # angle_approach(float*, float, float)
print(oracle.read_f32(angle))
```

## Running the differential tests

The executable lives under the gitignored `game_bins/`. Unicorn's JIT does not
run inside the agent command sandbox. For both reasons the tests are opt-in:

```bash
CRIMSON_NATIVE_ORACLE=1 uv run pytest tests/native_oracle
```

Without the variable, or without the executable, the tests are skipped. A
failure lists mismatching fields grouped by kind. `bits` means the float32
or integer value differs. `unrounded` means the float32 bits agree, but the port
stores a wider double where native stores a float32.

| Test | Native code | Port |
| --- | --- | --- |
| `test_float_helpers` | `angle_approach` `0x0041f430`, `__ftol` `0x00461054`, PC24 `fadd`/`fsub`/`fmul`/`fdiv`/`fsqrt`, `fcos`/`fsin` + `fmul` | `_angle_approach`, `ftol_ms_i32`, `math_parity.x87_pc24_*` |
| `test_spawn_template` | `creature_spawn_template` `0x00430af0`, every template × hardcore × retry count | `CreaturePool.spawn_template` |
| `test_projectiles` | `projectile_spawn` `0x00420440`; shotgun pellets in `player_fire_weapon` `0x00444980`; flamer and Bubblegun fire block of `player_update` `0x00415a1f..0x004174c4` | `ProjectilePool.spawn`, `fire_weapon` |
| `test_projectile_update` | `projectile_update` `0x00420b90`: rocket flight, detonation blast, Shrinkifier/Splitter/Plasma Cannon/Ion Rifle hits; Shock Chain in `bonus_apply` `0x00409890` | `SecondaryProjectilePool.step`, `ProjectilePool.step`, `bonus_apply` |
| `test_typo_spawn` | Typ-o spawn block `0x00445a62..0x00445c85` with `creature_spawn_tinted` | `typo_mid_step` |
| `test_quest_builders` | All 50 `quest_build_*` functions (`0x00434480..0x004390d0`) across seeds, terrain sizes, player counts and hardcore | `QuestDefinition.builder` spawn tables |
| `test_mode_spawns` | `rush_mode_update` `0x004072b0` with `creature_spawn`; `survival_spawn_creature` `0x00407510`, including elapsed times and experience past 2^24 | `tick_rush_mode_spawns`, `build_survival_spawn_creature` |
| `test_creature_xp` | Quick Learner and plain kill XP in `creature_handle_death` `0x0041eb34..0x0041eb6e`; Radioactive kill XP `0x0042704b..0x00427062`; Jinxed kill XP `0x004070a6..0x004070cf` | `quick_learner_kill_xp`, `experience_plus_reward` |
| `test_creature_anim` | Animation phase step in `creature_update_all` `0x00426e22..0x00426f35` | `creature_anim_advance_phase` |
| `test_camera_shake` | `camera_update` `0x00409500` over whole Nuke shakes | `camera_shake_update` |
| `test_sprite_effects` | Sprite loop of `projectile_update` `0x0042246a..0x004224e8` | `SpriteEffectPool.update` |

## Limitations

- Unicorn evaluates `fsin`, `fcos`, `fpatan` and the other transcendentals with
  host double `libm`. PC24 rounding of `fadd`/`fsub`/`fmul`/`fdiv`/`fsqrt` is
  exact. The oracle therefore checks the rounding structure around trig, not
  extended-precision trig accuracy.
- Code that reaches Direct3D, DirectInput, audio or the `grim.dll` vtable
  traps. Stub those callees, as the tests stub `sfx_play_panned` and
  `console_printf`.
- Globals start from the executable's file image plus static initializers.
  Runtime tables that game startup fills, such as perk ids, must be seeded or
  built by calling their init functions (`weapon_table_init`,
  `effect_defaults_reset`). `prepare_gameplay` in `tests/native_oracle/_support.py`
  seeds what `projectile_update` and the fire paths need, including binding
  `vec2_normalize_impl` to the x87 `d3dx_c_vec2_normalize`: the lazy D3DX
  dispatcher would otherwise probe the registry and CPU features.
