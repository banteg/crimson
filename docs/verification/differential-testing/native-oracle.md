---
tags:
  - verification
  - differential-testing
  - float-parity
---

# Native execution oracle

`crimson_re.dbg.native_oracle` runs functions of the original `crimsonland.exe`
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
  applies C++ defaults such as the weapon-table projectile speeds. The CRT
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
from crimson_re.dbg.native_oracle import NativeOracle

oracle = NativeOracle()
oracle.run_static_initializers()
angle = oracle.alloc_f32s(1.0)
oracle.write_f32("frame_dt", 0.016)
oracle.call("angle_approach", angle, 2.0, 3.0)  # angle_approach(float*, float, float)
print(oracle.read_f32(angle))
```

## Running the differential tests

The executable lives under the gitignored `game_bins/`, and Unicorn's JIT does
not run inside the agent command sandbox, so locally the tests are opt-in. CI
downloads the hash-checked 1.9.93 binaries and runs them on every push:

```bash
CRIMSON_NATIVE_ORACLE=1 uv run pytest tests/native_oracle
```

Without the variable, or without the executable, the tests are skipped. A
failure lists mismatching fields grouped by kind. `bits` means the float32
or integer value differs. `unrounded` means the float32 bits agree, but the port
stores a wider double where native stores a float32.

Apart from `test_harness`, which checks the oracle itself, each module in
`tests/native_oracle/` opens with the native function or address range it runs
and the port code it checks.

## Limitations

- Unicorn evaluates `fsin`, `fcos`, `fpatan` and the other transcendentals with
  host double `libm`. PC24 rounding of `fadd`/`fsub`/`fmul`/`fdiv`/`fsqrt` is
  exact. The oracle therefore checks the rounding structure around trig, not
  extended-precision trig accuracy.
- Code that reaches Direct3D, DirectInput or audio traps. Stub those callees,
  as the tests stub `sfx_play_panned` and `console_printf`. For the `grim.dll`
  vtable, `install_fake_grim` in `tests/native_oracle/_support.py` installs an
  interface whose methods return 0 or run per-method handlers.
- Globals start from the executable's file image plus static initializers.
  Runtime tables that game startup fills, such as perk ids, must be seeded or
  built by calling their init functions (`weapon_table_init`,
  `effect_defaults_reset`). `prepare_gameplay` in `tests/native_oracle/_support.py`
  seeds what `projectile_update` and the fire paths need, including binding
  `vec2_normalize_impl` to the x87 `d3dx_c_vec2_normalize`: the lazy D3DX
  dispatcher would otherwise probe the registry and CPU features.
