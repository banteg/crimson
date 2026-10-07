# Native and web port

The plan for a playable native and web build of the recovered game, the seam it
ports at, and what each phase has established. Started 2026-10-07; updated as
phases land.

## Summary

The whole recovered game is one wasm32 **game module**: every executable and
Grim source file except a small Windows surface. The port replaces only what
lies below Grim: a Direct3D 8 device, DirectInput, DirectSound and a few Win32
calls, implemented over a small host interface. One C host (SDL3 and an owned
OpenGL renderer) runs the module natively, and the same host is meant for the
browser.

The module runs two ways. **As the original** (`game_start`, `game_frame`), it
is the 2003 executable: its startup, menus, variable timestep and input, one
frame per host callback. **As a session** (`portable_init`,
`portable_step_many`), it is the verifier: fixed ticks fed a recorded input
tuple, where Grim answers input and time queries exactly as the headless
verifier does and gameplay RNG may only be drawn inside run start and ticks.
Everything the module sends the host returns nothing, so presentation cannot
feed back into either.

Python stays the reference port and the desktop product until the client plays
sessions that pass the gates below.

## Architecture

### The seam is below Grim

The spec first placed the seam at the Grim2D interface, reimplementing its 84
methods over a modern renderer. Compiling the recovered Grim changed that: 147
of its 171 source files build for wasm32 unmodified, and the rest are window,
dialog and device-creation code. The recovered Grim already reproduces the
original's vertex math, text layout, batching, texture slots and render
targets; Python's [`src/grim`](../src/grim) shows how many quirks a
reimplementation has to chase instead (UV insets, rotation origins, blend state
across mode switches, render-target nesting).

So Grim2D stays the interface between the executable and Grim, both inside the
module, and the platform layer ([`game/`](game)) implements the Windows surface
they use:

| Original | Replacement |
| --- | --- |
| Direct3D 8 device, textures, surfaces, vertex and index buffers (about 40 methods) | [`platform.cpp`](game/platform.cpp) forwards draws, state and texels to the host |
| D3DX texture loading (TGA, BMP, JPEG) | [`d3dx.cpp`](game/d3dx.cpp), with the IJG libjpeg 6a and zlib 1.1.3 Grim links |
| DirectInput keyboard and mouse | [`dinput.cpp`](game/dinput.cpp): device state the host delivers each frame |
| Grim's window procedure and run loop | [`frame.cpp`](game/frame.cpp): one loop pass per host frame; window messages as calls |
| `grim.dll`'s embedded font and splash | [`resources.cpp`](game/resources.cpp) reads them from `grim.dll` |
| Files, registry, threads, WinInet, DLLs | [`win32.cpp`](game/win32.cpp): Windows paths under the game directory, a registry file, threads that run to completion, offline WinInet, no DLLs |
| DirectSound and vorbisfile | Silent for now: the original's no-sound path |
| The executable's static initializers | Run in the order of its `.CRT$XCU` table ([`game.py`](game.py)) |

Any COM method the platform layer does not implement stops the module with its
name: [`game.py`](game.py) generates the defaults from the Wine headers.
wasm32 keeps the original pointer width, so each image's globals keep their
original layout (`game_data` in [`game.py`](game.py)): aggregates read through
a first symbol, overreads and interior names land on the original bytes.

Compiling the rest of the executable needed the same kind of declaration
repairs `adapter.py` makes for the verifier, for signatures the recovered files
disagree on and wasm32 calls cannot tolerate; [`game.py`](game.py) lists each.

### The host interface

[`game/host_abi.h`](game/host_abi.h) is the whole presentation boundary:
textures, render and texture-stage states, draws, present, gamma and message
boxes return nothing. The only query is wall time. Files arrive through WASI,
rooted at the game directory.

### The tick seam

[`host/game.inc`](host/game.inc) wraps the recovered Grim. During
`portable_init` and `portable_step_many`, every input and time query answers as
the verifier's headless Grim does, and the executable's own session-sensitive
functions (`game_state_set`, the run-down timeline, primary input, play time)
take the verifier's behaviour. Outside those scopes the recovered behaviour
runs. In a session, `crt_rand` aborts outside run start and ticks.

Headless, a session sets Grim's own `grim_render_disabled` switch and owns a
device that never becomes ready: the recovered state calls run, and draws stop
inside Grim.

### Evidence

- [`checks/game_check.py`](checks/game_check.py) runs sessions in the game
  module and the verifier through every gate stream (the 134-run bot corpus
  under both bug policies and the 8 supported recordings) and compares all
  36,343 snapshot fields after every tick; where a run ends, both must refuse
  the next tick. All 142 agree, with the whole executable linked. The one
  expected difference is `player_weapon_popup_timer`, which the restored HUD
  counts down and only the HUD reads.
- [`checks/game_boot.mjs`](checks/game_boot.mjs) boots the original from a fresh
  game directory under Node's WASI, clicks through the menus into Survival, and
  requires every texture to load and the run to keep drawing.

The verifier's hand-set cvars differ from the registered defaults for two
values it never reads: terrain body transparency (verifier 0.8, original 0) and
pad aim distance (verifier 128, original 96; recorded pad aim replaces it).

### Packaging

The native client embeds the module through `wasm2c`, so the simulation keeps
wasm32 layout everywhere. The browser build uses the same host through
Emscripten. The verifier converges onto the game module once the client plays
sessions: the Worker instantiates the same module with presentation imports
that are never called, and the 64-bit native core build retires.

### Assets

The client reads the original game directory: `grim.dll` and the three PAQs
(the configuration files appear on first launch). The asset host's PAQs are the
Python port's repack, with forward-slash names and replaced art, which the
original lookup cannot read; serving the original files as well would let the
client and CI fetch them.

## Stack

**SDL3** for windows, input, gamepads, audio output, storage and the main loop
(SDL main callbacks, so the browser build needs no Asyncify). **An owned
OpenGL renderer** ([`client/renderer.cpp`](client/renderer.cpp), GLSL 330
natively, GLSL 300 ES / WebGL2 in the browser) implements the Direct3D 8 subset
the device receives: pre-transformed 28-byte vertices with Direct3D's pixel
centers, two fixed-function texture stages, raw `D3DBLEND` factors, alpha test,
colour-write masks with X8R8G8B8 targets keeping alpha at one, render targets,
per-stage filtering and addressing, and the gamma ramp at present.

Neither SDL rendering API fits: SDL_GPU has no WebGL backend (its WebGPU
backend is an [experimental PR](https://github.com/libsdl-org/SDL/pull/16020)),
and SDL_Renderer has no alpha test or write masks. raylib would mean fitting
Grim's device state around rlgl and raudio; keep it for the Python port, where
its workarounds are already solved.

## Running the native client

```sh
uv run python crimson-core/client/build.py      # game module, wasm2c, SDL3 host
crimson-core/build/app/crimson <game directory>
```

It needs wabt's `wasm2c`, SDL3 and the original game directory. For
unattended runs, `CRIMSON_CAPTURE=<dir>` with `CRIMSON_CAPTURE_FRAMES=n,...`
saves those frames' back buffers and quits, and `CRIMSON_INPUT` scripts the
mouse and keys ([`client/main.cpp`](client/main.cpp)).

## Plan

| Phase | Delivers | State |
| --- | --- | --- |
| 1. Game module | Recovered Grim and presentation in wasm32; sessions match the verifier on all gate streams | Done ([#550](https://github.com/banteg/crimson/pull/550)) |
| 2. Native client | The whole executable in the module; SDL3/OpenGL host over `wasm2c`; the original game boots, menus and runs play | This change |
| 3. Web client | The same host through Emscripten | |
| 4. Audio | DirectSound and vorbisfile over a host mixer; voice stealing on its own RNG | |
| 5. Sessions in the client | Gameplay as fixed ticks fed recorded input; perk picks as commands; replays; the client artifact passes the gates | |
| 6. Verifier convergence | The service and gate run the game module; the native core retires | |
| 7. Product parity | Controllers, letterboxing options, replay browsing, ranked upload | |
| 8. Distribution | Packaged desktop builds and the hosted web build | |

## Acceptance gates

| Gate | Evidence required |
| --- | --- |
| Simulation | Every gate stream through each release artifact agrees with the verifier on every snapshot field after every tick. |
| Session | Identical input and commands at 30, 60 and 144 Hz display rates, including frames with zero or several ticks, pauses, perk and menu transitions, restarts and tab suspension, give identical state and results. |
| Audio | Identical simulation results with real audio, a null sink, muting, autoplay lock, voice saturation and device failure. |
| Graphics | Captures of terrain persistence, corpse and decal bakes, alpha threshold, blend factors, write masks, fonts, texture edges and gamma against the original, with documented tolerances. |
| Persistence | Saves survive relaunch and reload; a failed asset or storage operation is visible and never changes a ranked run's setup. |
