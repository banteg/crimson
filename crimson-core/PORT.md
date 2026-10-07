# Native and web port

How far the recovered source is from a playable native and web build, the seam
to port at, and the stack to port with. Researched 2026-10-07.

## Summary

The supported simulation is already portable: the recovered core runs as
import-free WASM, the service uses it to verify ranked runs, and the checked-in
native/WASM matrix agrees over 357,500 ticks. This covers single-player
Survival, Rush and all 50 Quests, not the whole game. There is no playable C
client yet. Menus, resources, sound and the platform layer are recovered but
have never been built by a modern compiler.

Recommendation: port at the **Grim2D interface plus explicit platform and
session contracts**, **web first**, using **SDL3 and an owned OpenGL renderer**:
GLES3/WebGL2 in the browser, desktop OpenGL on macOS/Linux/Windows. Keep Python
as the reference product. Prefer this over raylib for the C client because we
need precise graphics state and control of audio side effects.

First deliver Quest 1.1 in the browser with terrain, corpses, HUD, perk
selection and sound, and prove replay parity in that client. It does not need
every recovered file. A faithful original client and parity with the Python
product are separate milestones; estimate them once the slice has exercised the
missing systems.

## Where we are

| Piece | State |
| --- | --- |
| Simulation | The core compiles 168 of the exe's 576 source files: 20,220 of 44,850 source lines, producing roughly 356 KiB of import-free WASM. The service verifier is [`service/src/verify.ts`](../service/src/verify.ts). See [supported scope](README.md), [replay gate](results/gate.json) and [native/WASM matrix](results/matrix.json). |
| Rest of the exe | Menus, UI, high scores, sound, resources, typ-o, console, credits: byte-exact under VC6 ([matching report](../tools/match/STATUS.md)) but outside the core build. Expect more of the declaration and layout repairs [`adapter.py`](adapter.py) already makes. |
| Grim | 84 vtable slots, 60 called by the exe from 111 files ([`grim2d_cpp.h`](../tools/match/include/grim2d_cpp.h), [API docs](../docs/grim2d/api.md)). The core uses a headless implementation in [`host/grim.inc`](host/grim.inc); recovered Grim is not a modern backend. Python's [`src/grim`](../src/grim) is the working reference for rendering and audio. |
| Direct platform calls in the exe | Registry, DirectSound with vorbisfile (`sound/`, `platform/vorbis_*`), WinInet high-score threads, ShellExecute, Sleep and timeGetTime, mod DLLs via LoadLibrary. Each needs an explicit replacement or unsupported disposition; original Windows mod DLLs cannot run in the web client. |
| Runnable full build | None, with MSVC or anything else. The native link has only checked a passive grim component. |
| Python product features | Twin-stick controllers, letterboxing, 3–4 player co-op, replay recording, ranked upload and identity, the bug fixes outside the core's 12 patches. This is the long tail. |

The checked-in replay gate reports 142/142 supported fixtures agreeing, with
Typ-o explicitly unsupported. The matrix validates the selected headless
simulation across 134 cases. Neither covers the missing client code.

### Not yet compiled by the core

Nothing from `console`, `credits`, `dxversion`, `end_screens`, `highscore`,
`menus`, `mods`, `platform`, `resource`, `sound`, `typo`, `ui_elements`,
`ui_screens` or `ui_widgets`. Partial: `crimsonland` 46/121, `game` 12/43,
`gameplay` 15/32, `ui_render` 5/28, `audio` 3/26, `effects` 17/23. No grim
source is compiled.

### Portability hazards

- No `__asm`, SEH or C++ exceptions. Grim's JAZ decoder uses setjmp/longjmp.
- About 23 obvious pointer/int casts. `grim_config_value_t` is a four-word
  `unsigned int words[4]` payload; its pointer constructor uses slot 3. The
  pointer-bearing configuration sites, fixed mod API layout and metadata
  pointer strides ([`data.py`](data.py)) need auditing. wasm32 avoids pointer
  widening, but does not repair absolute addresses, relocations, or mismatched
  function-pointer signatures. Use a correctly typed frame callback.
- x87 PC24, intermediate precision and wide trig results until the first
  multiply matter to the existing core. Preserve its build flags and portable
  math. Audit newly included routines by their effect on authoritative state;
  being named UI or render does not exempt a routine from numeric adaptation.
- Keep the VC6 CRT `rand` LCG exact wherever it is authoritative. 64 files call
  `crt_rand` and `sfx_entry_start_playback.cpp` calls `rand` directly; each call
  is either authoritative or presentation, never blanket-forwarded to one RNG.
  In the client build, make the authoritative `crt_rand` abort when called
  outside a simulation tick, so the build lists the presentation callers
  instead of an audit having to find them.
- `D3DXVec2Normalize` is covered for current core callers; new callers and new
  compiler targets need parity checks, and aliasing and layout assumptions need
  review as the dependency closure grows.

## Seam: the Grim2D interface

Keep `IGrim2D_cpp` as the graphics/resource seam, plus a thin platform layer for
direct OS calls. Treat it as a stateful contract: font metrics, resource IDs,
configuration reads and return values affect recovered code. Only operations
proved irrelevant to the selected simulation may be no-ops in the verifier.

| Original | Replacement |
| --- | --- |
| Registry (`reg_read_dword_default`, `reg_write_dword`, saves, play time) | Per-user config/save files natively; an explicit asynchronous IndexedDB adapter on the web |
| DirectSound buffers and vorbisfile (`sound/`, `platform/vorbis_*`) | Our own mixer and Ogg decoder, with playback state kept outside authoritative RNG |
| WinInet high-score and update threads | Disable the original network paths for the first client; integrate the existing service protocol later |
| ShellExecute, HlinkNavigateString | The host's URL opener |
| Sleep, timeGetTime, QueryPerformanceCounter | Host/UI timing; simulation time comes from the fixed-tick session contract |
| Mod DLLs | Off |
| Texture/font loading and text measurement | Stable resource metadata shared with the headless implementation; GPU handles remain presentation details |

Why this seam:

- **The original authors drew it.** The exe already uses `grim2d_cpp.h`, and the
  core's headless Grim implements that interface. Python provides reference
  behavior for the parts a real backend must restore.
- **Its control flow fits the web.** Grim's `apply_settings` is the message
  loop, and it calls the frame function the exe installs with
  `set_config_var(0x2d, …)`. Replace ownership of that loop with SDL3 main
  callbacks and a typed frame entry point. Initialize assets asynchronously
  before entering gameplay; a callback-driven loop need not require Asyncify.
- **Simulation and presentation can be separated explicitly.** Sound choice,
  playlist selection, camera shake and persistent effects have authoritative
  work to preserve. Real device state must not feed back into those decisions.

### Session rules come before the backend

Extend the existing [host API](host/api.h), [roadmap](ROADMAP.md) and Python
[clock](../src/crimson/sim/clock.py)/[run result](../src/crimson/sim/run_result.py)
contracts, rather than allowing the original OS loop to define a second policy:

- Gameplay consumes normalized finite input and ordered commands at fixed
  60 Hz boundaries. Preserve the core's float32 time arithmetic, Reflex Boost
  behavior and once-per-tick work; host wall time must not become gameplay dt.
- Sample controllers/mouse through a specified mapping to the existing input
  ABI. Record the float32 values actually submitted to the core. Ranked runs
  use the [canonical rules](../docs/rewrite/ranked-rules.md), including aim and
  viewport constraints, rather than current window dimensions.
- Menus and fully paused/perk-selection screens do not advance gameplay time
  or authoritative RNG. Preserve the existing transition ticks before a pause
  becomes effective. Clear accumulated gameplay debt on session transitions;
  resuming a tab must not replay seconds of missed gameplay.
- Perk picks and menu requests use the command seam. Preserve validation,
  ordering and tick placement; UI code must not mutate gameplay directly.
- Define terminal versus incomplete runs and the simulated 500 ms run-down.
  Compare the complete `RunResult`, including pending perks and final RNG,
  rather than only a death/completion flag or score.

Rendering is not yet a pure observer. The recovered world render path contains
weapon checks and effect-queue work. Some headless state-transition and UI
stubs also omit side effects (see the roadmap's stub audit). Execute every
authoritative operation once per tick, including persistent terrain/corpse
bakes. For a display frame with zero or several ticks, submit persistent work
from every tick and only the latest transient scene. Detached menu animation
may use presentation time and a separate RNG. Do not simply skip all render
routines between display frames.

### Packaging: preserve the shared core until the client proves parity

The [roadmap](ROADMAP.md#client-milestone-the-whole-recovered-game) prefers one
wasm32 simulation artifact for browser, verifier and desktop host. That remains
the release baseline. A linked Emscripten game/backend is a candidate to test in
the first slice, not a property established by the current native/WASM matrix.

Both designs can use one C renderer compiled per platform:

| Design | Benefit | Cost and condition |
| --- | --- | --- |
| Shared simulation WASM; host consumes ordered Grim commands | Client and verifier execute identical simulation bytes; desktop can host the module with Wasmtime | Define command/resource lifetimes and synchronous metadata queries; measure boundary overhead. A JavaScript bridge does not require rewriting the renderer in JavaScript. |
| Game and SDL/GL backend linked into each client | Direct calls and simpler initial resource ownership | Different simulation artifacts and additional recovered routines; prove each release artifact against the verifier, including active rendering and audio. A headless rebuild of client sources is insufficient. |

Prototype the linked route if it speeds up the slice. Adopt it only after the
client passes the gates below and measured benefits justify departing from the
roadmap. If restored code changes state, reconcile the authoritative contract
first; a matching snapshot layout does not show omitted state is irrelevant.

### Web first

wasm32 keeps the original pointer width, so it needs only the relocation and
callback audit above. Prove the browser slice before expanding the 64-bit layout
adaptations; a native SDL host for the same wasm32 core is the alternative to a
64-bit simulation rebuild. Python stays the desktop product meanwhile.

## Stack: SDL3, owned GL renderer, Emscripten

### Rendering: GLES3/WebGL2 on web, desktop GL on native

Use shared renderer code with GLSL 300 ES and GLSL 330 shader variants.
On macOS, SDL's Cocoa GLES path uses EGL; it is not the ordinary CGL desktop
OpenGL path ([SDL implementation](https://raw.githubusercontent.com/libsdl-org/SDL/main/src/video/cocoa/SDL_cocoaopengl.m)).
Choose desktop OpenGL for the first native backend. ANGLE/EGL is an explicit
future dependency choice if one GLES path becomes preferable.

Implement the D3D8 subset Grim uses:

- 28-byte XYZRHW + diffuse + one texture coordinate vertices, D3DCOLOR packing;
- raw `D3DBLEND` factors through config 0x13/0x14, including separate alpha
  factors for the ZERO/INV_SRC_ALPHA darken pass;
- alpha test greater than 4/255;
- colour-write mask so RGBA targets behave like the original XRGB surfaces;
- render targets for the persistent 1024×1024 terrain, with incremental decal
  and corpse bakes;
- point or bilinear filtering per texture (config 0x15);
- gamma (config 0x1c), with an explicit approximation of the original ramp
  validated against captures;
- texture addressing, render-target orientation and D3D pixel-center rules;
- strict original draw order; batch only adjacent compatible draws, without
  sorting translucent draws or reordering render-target updates;
- resize/HiDPI/fullscreen handling and restoration of persistent targets after
  WebGL context loss, without changing simulation state.

Neither SDL rendering API fits:

- **SDL_GPU** has no WebGL backend; its WebGPU backend is still an
  [experimental PR](https://github.com/libsdl-org/SDL/pull/16020).
- **SDL_Renderer** supports custom fragment shaders through its GPU renderer,
  but that is not a WebGL solution. Alpha testing, write masks and the exact
  D3D blend/state contract favor owning GL directly
  ([SDL FAQ](https://wiki.libsdl.org/SDL3/FAQDevelopment)).

### Platform: SDL3

- SDL gamepad mappings, hot-plug and positional button labels; controller
  support still needs the game's input and aim mapping.
- Window/events and platform selection, including Wayland on Linux.
- `SDL_GetPrefPath` for native saves and `SDL_AudioStream` for audio output.
- SDL main callbacks for desktop and Emscripten. Keep asset loading, persistence
  and network activity out of blocking frame callbacks.

Browser execution has additional contracts: yield to the browser each frame,
render on the main thread initially, unlock audio with a user gesture, and
handle tab suspension. MEMFS is ephemeral; load saved data before session
initialization and flush IndexedDB explicitly. Avoid pthreads initially;
enabling them adds cross-origin isolation requirements. Pin SDL/Emscripten
versions and record the actual build options
([SDL Emscripten guide](https://wiki.libsdl.org/SDL3/README-emscripten)).

### Resources

Use a reproducible asset manifest with stable IDs and dimensions, and shared
font metrics for the client and verifier. GPU allocations or asynchronous load
order must not determine IDs or authoritative return values. For the first
slice, converting PAQ/JAZ assets at build time is reasonable; shipping the
original archive/decoder path can follow when needed. The existing Python
asset pipeline supplies reference behavior. Bootstrap required assets before
starting a run, and make missing assets a visible initialization failure.

### Audio

Use an Ogg decoder (evaluate stb_vorbis versus libvorbis on the slice) and a
small mixer: 16 voices per sample, per-voice pitch, DirectSound pan/attenuation
in hundredths of a dB, and streamed music with manual fades. Preserve the
Reflex Boost sample-rate behavior (44100 down to 22050). Select the decoder
using actual asset compatibility, memory use and decode cost.

**Real audio playback must not choose authoritative RNG draws.** Recovered
[`sfx_entry_start_playback.cpp`](../decomp/1.9/crimsonland/sound/sfx_entry_start_playback.cpp)
queries DirectSound status, takes the first idle voice, or calls `rand() % 16`
when all voices are busy. The core currently stubs playback; restoring this
path unchanged would make core RNG depend on device timing and muting.

Keep authoritative sound/music selection and its RNG consumption on the
simulation side, including when audio is unavailable. Use a separate
presentation RNG for first-idle-else-random voice stealing, as Python's
[`audio_bridge.py`](../src/crimson/world/audio_bridge.py) does with `audio_rng`.
This follows the existing replay policy, not the original device-dependent
behavior. Audit music-ready gates and backend return values as well: the headless host
deliberately represents silent, successfully initialized audio. Exercise muted,
unlocked, saturated and failed-device paths in parity checks.

### Why not raylib for the C port

raylib would get a demo running quickly: it targets desktop GL and WebGL and
has an SDL3 platform backend
([raylib platforms](https://github.com/raysan5/raylib/wiki/raylib-platforms-and-graphics)).
The tradeoff is fitting Grim's state machine around rlgl and raudio versus
owning that small subset directly.

Python shows the specific adaptation work: render-target nesting
([`texture_mode.py`](../src/grim/texture_mode.py)), blend state across mode
switches ([`blend.py`](../src/grim/blend.py)), texture orientation and
DirectSound pan ([`audio_math.py`](../src/grim/audio_math.py)). Owning the mixer
also makes separation of authoritative and playback-dependent RNG explicit.

Other Python workarounds apply to either stack: alpha test needs a discard
shader in owned GL too, web shaders need ES variants, and C raylib can drop F12
capture with `SUPPORT_SCREEN_CAPTURE=0`
([raylib config](https://raw.githubusercontent.com/raysan5/raylib/6.0/src/config.h)).
The Python fullscreen and HiDPI issues are regression cases for either backend.

**Choose SDL3 plus owned GL for the C client; keep raylib for Python.**
Revisit if the slice shows renderer or audio work dominating and raylib
removing it without losing parity.

## Plan

1. **Freeze session and dependency contracts.** Specify clocks, input/commands,
   run completion, authoritative versus presentation RNG, resource queries and
   render side effects. Inventory the dependency closure for Quest 1.1. Add
   files incrementally in [`build.py`](build.py); unsupported paths fail
   visibly. Add the out-of-tick `crt_rand` abort before restoring any
   presentation code. The existing core build and corpus stay the baseline.
2. **Quest 1.1 in the browser.** SDL callbacks, required assets, terrain and
   corpse render targets, player/enemy/projectile rendering, HUD, perk
   selection, mixer and replay recording, including restart and completion.
   The gate already carries a human recording of it
   ([`quest-1.1-completed.crd`](results/gate.json), 1,441 ticks, ranked rules)
   and the bot completes it, so the client starts with known-good references.
   Evaluate linked versus shared-module packaging here. Exit when the client
   replays that recording to the same `RunResult`, its own fresh recordings
   verify, and it passes the session and audio gates below. This is the first
   playable milestone.
3. **Complete the supported single-player client.** Grow the closure for all
   Quests, Survival and Rush; restore menus, options, progress/high scores and
   reliable browser persistence. Audit state transitions and initialization
   omitted by the headless build. Compare UI and gameplay captures with Python
   and original references. Tutorial, Typ-o, console, credits and other omitted
   paths need explicit follow-up scopes before claiming the whole original
   game. Windows mod DLLs and original network endpoints remain disabled.
4. **Native host and distribution.** Reuse the renderer with desktop GL shaders;
   validate macOS/Linux/Windows resource paths, audio, HiDPI and fullscreen.
   Choose a wasm32 host or native simulation build based on measured startup,
   distribution cost and parity; adapt 64-bit recovered layouts only if the
   native simulation route is justified. Native renderer smoke checks can run
   earlier without porting the whole executable.
5. **Python product parity and ranked release.** Controller mappings,
   letterboxing, co-op, remaining bug fixes and UI, replay browsing, identity
   and upload. Follow the existing [ranked rules](../docs/rewrite/ranked-rules.md)
   and [identity protocol](../docs/rewrite/leaderboard-identity.md), including
   canonical runs detached from ordinary save progress. Reconcile unsupported
   modes/player counts explicitly; co-op is beyond the current core contract.
   Ranked release requires the artifact gates below, but need not wait for
   co-op or other unsupported modes.

## Acceptance gates

| Gate | Evidence required |
| --- | --- |
| Simulation | Run the supported replay corpus under both bug policies through the actual release client artifact and the verifier. Compare per-tick authoritative state and complete terminal/incomplete results. Keep unsupported fixtures visible. Extend probes when restored code introduces state outside current snapshots. |
| Session | Replay identical normalized input/commands at 30/60/144 Hz display rates, including zero/multiple ticks per frame, pause/perk/menu transitions, restart and tab suspension. State/RNG/results must agree; UI time must not change command placement. |
| Audio | Identical simulation results with real audio, a null sink, muting, autoplay lock, voice saturation and device failure. Verify music selection/gates as well as SFX; perceptual pan/pitch/fade checks are separate. |
| Graphics | Targeted captures for terrain persistence, corpse/decal bakes, alpha threshold, blend factors, write masks, fonts, texture edges and gamma. Document tolerances for rasterization differences. Test resize, HiDPI/fullscreen and web context restoration. Pixels may differ within justified tolerances; authoritative state may not. |
| Resources and persistence | Stable resource IDs/metrics across loading order and backend; fresh launch and reload preserve saves. A failed asset or IndexedDB operation is surfaced and does not silently alter a ranked run's canonical setup. |
| Packaging | Record source revision, compiler/SDL/Emscripten versions, flags and hashes. Linked builds must pass artifact parity for every release target; a separate headless variant is not release evidence. Shared-core builds must verify core byte identity and still test the real host's session/render/audio behavior. |

The existing matrix covers the supported simulation; these gates check that
the client preserves it. Quest 1.1 tests the seam and stack long before all 576
files build.
