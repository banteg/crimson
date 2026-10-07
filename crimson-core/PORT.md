# Native and web port

The plan for a playable native and web build of the recovered game, the seam it
ports at, and what each phase has established. Started 2026-10-07; updated as
phases land.

## Summary

The recovered game becomes one wasm32 **game module**: the verifier's gameplay
selection plus the recovered presentation code and the recovered Grim engine.
The port replaces only what lies below Grim: a Direct3D 8 device, DirectInput,
DirectSound and a few Win32 calls, implemented over a small host interface. One
C host (SDL3 and an owned OpenGL renderer) runs that module natively and in the
browser.

The module keeps ranked integrity structural. Inside run start and simulation
ticks, Grim answers input and time queries exactly as the headless verifier
does, and gameplay RNG may only be drawn there. Everything the module sends the
host returns nothing, so presentation cannot feed back into the simulation.

Python stays the reference port and the desktop product until the client passes
the gates below.

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
module, and the platform layer implements the Windows surface Grim uses:

| Original | Replacement |
| --- | --- |
| Direct3D 8 device, textures, surfaces, vertex and index buffers (about 40 methods) | [`game/platform.cpp`](game/platform.cpp) forwards draws, state and texels to the host |
| DirectInput keyboard, mouse and joystick | Device state the host delivers each frame |
| DirectSound buffers and vorbisfile (`sound/`, `platform/vorbis_*`) | A host mixer; voice stealing uses its own RNG |
| Registry, files, embedded `grim.dll` resources | Host asset reads and per-user storage |
| `timeGetTime`, `Sleep` | Host wall time, read only outside ticks |
| Windows, dialogs, device reset | Not needed: the host owns the window |
| WinInet, ShellExecute, mod DLLs | Off for now; the service protocol replaces score submission later |

Any COM method the platform layer does not implement stops the module with its
name: [`game.py`](game.py) generates the defaults from the Wine headers.

### The host interface

[`game/host_abi.h`](game/host_abi.h) is the whole boundary. Presentation calls
(textures, render and texture-stage states, draws, present, gamma) return
nothing. The only queries are wall time and asset bytes; a tick never reads
either.

### The tick seam

[`host/game.inc`](host/game.inc) wraps the recovered Grim. During
`portable_init` and `portable_step_many`, every input and time query answers as
the verifier's headless Grim does, so live input reaches gameplay only through
the recorded input tuple, exactly as in verification. Outside those scopes,
menus read the real devices and clock. `crt_rand` aborts outside them, so
presentation code cannot draw gameplay RNG.

Headless, the module sets Grim's own `grim_render_disabled` switch and owns a
device that never becomes ready: the recovered state calls run, and draws stop
inside Grim.

### Evidence

[`checks/game_check.py`](checks/game_check.py) steps the game module and the
verifier through every gate stream (the 134-run bot corpus under both bug
policies and the 8 supported recordings) and compares all 36,343 snapshot
fields after every tick; where a run ends, both must refuse the next tick. All
142 agree. The one expected difference is `player_weapon_popup_timer`, which the
restored HUD counts down and only the HUD reads
([`checks/game_compare.mjs`](checks/game_compare.mjs)).

During a run the host owns the run-down, as in the verifier, so the restored UI
timeline that drives it in the original runs only outside ticks.

Restoring the original setup also showed that the verifier's hand-set cvars
differ from the registered defaults for two values it never reads: terrain body
transparency (verifier 0.8, original 0) and pad aim distance (verifier 128,
original 96; recorded pad aim replaces it).

### Packaging

The verifier converges onto the game module once the client exists: the
Worker instantiates the same module with presentation imports that are never
called. The native and web clients embed the module through `wasm2c`, so one C
host serves both and the simulation keeps wasm32 layout everywhere; the 64-bit
native core build retires with that convergence.

## Stack

**SDL3** for windows, input, gamepads, audio output, storage and the main loop
(SDL main callbacks, so the browser build needs no Asyncify). **An owned
OpenGL renderer** (GLSL 330 natively, GLSL 300 ES / WebGL2 in the browser)
implementing the Direct3D 8 subset the device receives: pre-transformed 28-byte
vertices, raw `D3DBLEND` factors, alpha test, colour-write masks, render
targets, filtering, gamma and strict draw order. Emscripten for the browser.

Neither SDL rendering API fits: SDL_GPU has no WebGL backend (its WebGPU
backend is an [experimental PR](https://github.com/libsdl-org/SDL/pull/16020)),
and SDL_Renderer has no alpha test or write masks. raylib would mean fitting
Grim's device state around rlgl and raudio; keep it for the Python port, where
its workarounds are already solved.

## Plan

| Phase | Delivers | State |
| --- | --- | --- |
| 1. Game module | `--target game`: recovered Grim and presentation in wasm32, headless parity with the verifier on all gate streams | This change |
| 2. Native client | SDL3/OpenGL host over `wasm2c`, assets and `grim.dll` resources, input, the frame loop; Quest 1.1 playable | |
| 3. Web client | The same host through Emscripten | |
| 4. Audio | DirectSound and vorbisfile over a host mixer | |
| 5. Single player | Menus, options, all modes, high scores, persistence | |
| 6. Verifier convergence | The service and gate run the game module; the native core retires | |
| 7. Product parity | Controllers, letterboxing, replays, ranked upload | |

## Acceptance gates

| Gate | Evidence required |
| --- | --- |
| Simulation | Every gate stream through each release artifact agrees with the verifier on every snapshot field after every tick. |
| Session | Identical input and commands at 30, 60 and 144 Hz display rates, including frames with zero or several ticks, pauses, perk and menu transitions, restarts and tab suspension, give identical state and results. |
| Audio | Identical simulation results with real audio, a null sink, muting, autoplay lock, voice saturation and device failure. |
| Graphics | Captures of terrain persistence, corpse and decal bakes, alpha threshold, blend factors, write masks, fonts, texture edges and gamma against the original, with documented tolerances. |
| Persistence | Saves survive relaunch and reload; a failed asset or storage operation is visible and never changes a ranked run's setup. |
