# Native and web port

How far the recovered source is from a playable native and web build, the seam
to port at, and the stack to port with. Researched 2026-10-07.

## Summary

The simulation part of a web port is done: the recovered gameplay already runs
as WASM in production and agrees bit for bit with Python and with native. What
remains is everything around it: about 60% of the exe source has never met a
modern compiler, nothing implements the 84-slot Grim2D interface on a modern
backend, and the exe's direct Win32, DirectSound and WinInet calls need
replacing.

Recommendation: port at the **Grim2D interface**, **web first**, on **SDL3 plus
a small GLES3/WebGL2 renderer** we own. Not raylib for the C port.

## Where we are

| Piece | State |
| --- | --- |
| Simulation | Done. The core compiles 168 of the exe's 576 source files (about 20k of 45k lines) to a 357 KiB import-free WASM module. The crimson.land Worker verifies ranked runs with it ([`service/src/verify.ts`](../service/src/verify.ts)). |
| Rest of the exe | Menus, UI, high scores, sound, resources, typ-o, console, credits: recovered and byte-exact, but never compiled by clang. Expect more of the declaration repairs [`adapter.py`](adapter.py) already makes. |
| Grim | 84 vtable slots, 60 called by the exe from 111 files ([`grim2d_cpp.h`](../tools/match/include/grim2d_cpp.h), [API docs](../docs/grim2d/api.md)). The only implementation is the headless no-op in [`host/grim.inc`](host/grim.inc). The Python [`src/grim`](../src/grim) (4.8k lines) is a validated reference backend. |
| Direct platform calls in the exe | Registry, DirectSound with vorbisfile (`sound/`, `platform/vorbis_*`), WinInet high-score threads, ShellExecute, Sleep and timeGetTime, mod DLLs via LoadLibrary. Each is small and replaceable; mods cannot run on the web. |
| Runnable full build | None, with MSVC or anything else. The native link has only checked a passive grim component. |
| Python product features | Twin-stick controllers, letterboxing, 3–4 player co-op, replay recording, ranked upload and identity, the bug fixes outside the core's 12 patches. This is the long tail. |

A faithful web build of the original game is moderately close. Parity with what
the Python port ships today is much further.

### Not yet compiled by the core

Nothing from `console`, `credits`, `dxversion`, `end_screens`, `highscore`,
`menus`, `mods`, `platform`, `resource`, `sound`, `typo`, `ui_elements`,
`ui_screens` or `ui_widgets`. Partial: `crimsonland` 46/121, `game` 12/43,
`gameplay` 15/32, `ui_render` 5/28, `audio` 3/26, `effects` 17/23. No grim
source is compiled.

### Portability hazards

- No `__asm`, SEH or C++ exceptions. Grim's JAZ decoder uses setjmp/longjmp.
- About 23 obvious pointer/int casts. The real 32-bit coupling is Grim's
  `grim_config_value_t`, which stores pointers in `unsigned int words[3]`
  (14 sites: window title, PAQ path, frame callback, HWND, device), the fixed
  mod API layout, and metadata tables with pointer strides
  ([`data.py`](data.py)). All harmless on wasm32.
- x87 PC24 and wide trig results until the first multiply. The adapter already
  handles the gameplay sites; UI and render code need no such treatment.
- The VC6 CRT `rand` LCG must stay exact (about 75 files use it).
- `D3DXVec2Normalize` must stay x87-exact; the core's portable math covers it.

## Seam: the Grim2D interface

Make `IGrim2D_cpp` the platform seam, plus a thin `platform_*` layer for the
exe's direct OS calls:

| Original | Replacement |
| --- | --- |
| Registry (`reg_read_dword_default`, `reg_write_dword`, saves, play time) | A config file in the per-user directory; IndexedDB on the web |
| DirectSound buffers and vorbisfile (`sound/`, `platform/vorbis_*`) | Our own mixer and an Ogg decoder |
| WinInet high-score and update threads | crimson.land, or off |
| ShellExecute, HlinkNavigateString | The host's URL opener |
| Sleep, timeGetTime, QueryPerformanceCounter | Host timing |
| Mod DLLs | Off |

Why this seam:

- **The original authors drew it.** The exe already compiles against
  `grim2d_cpp.h`, and the core's headless Grim already implements it. The
  verifier and the client become two implementations of one interface around
  the same compiled game.
- **Its control flow fits the web.** Grim's `apply_settings` is the message
  loop, and it calls the frame function the exe installs with
  `set_config_var(0x2d, …)`. That maps onto SDL3 main callbacks and
  `emscripten_set_main_loop` without Asyncify.
- **Audio splits cleanly.** The recovered `audio/` logic stays, because voice
  selection and the music gate consume RNG. Only the DirectSound and vorbisfile
  layer underneath is replaced.

### Backend linked in, not imported

The [roadmap](ROADMAP.md#client-milestone-the-whole-recovered-game) sketches
the host supplying Grim as WASM imports. With 84 fine-grained slots called
thousands of times a frame, that means a JavaScript backend, a second desktop
backend, and a command buffer to make the boundary cheap. A C backend compiled
per target is one implementation.

The cost is that the client's simulation is a separate build of the same
adapted sources, not the verifier's exact module. The native/WASM matrix
already shows those agree bit for bit over 357,500 ticks; add "the client build
replayed headless equals `core.wasm`" to it rather than requiring one module.

### Web first

wasm32 is ILP32, so the pointer-in-config sites and the mod API layout just
work. A 64-bit desktop build needs those 14 sites widened plus the existing
layout machinery, which matches the roadmap's advice not to expand it before a
real client exists. The Python port stays the desktop product until then.

## Stack: SDL3, GLES3 renderer, Emscripten

### Rendering: our own GLES3/WebGL2 renderer

About 1k lines implementing the D3D8 subset Grim uses:

- 28-byte XYZRHW + diffuse + one texture coordinate vertices, D3DCOLOR packing;
- raw `D3DBLEND` factors through config 0x13/0x14, including separate alpha
  factors for the ZERO/INV_SRC_ALPHA darken pass;
- alpha test greater than 4/255;
- colour-write mask so RGBA targets behave like the original XRGB surfaces;
- render targets for the persistent 1024×1024 terrain, with incremental decal
  and corpse bakes;
- point or bilinear filtering per texture (config 0x15);
- gamma through a full-frame gain pass (the original's config 0x1c ramp);
- strict native draw order, batched by pass.

Neither SDL3 rendering API fits:

- **SDL_GPU** has no WebGL backend; its WebGPU backend is still an
  [experimental PR](https://github.com/libsdl-org/SDL/pull/16020).
- **SDL_Renderer** has no alpha test, colour mask or custom shaders outside
  its GPU renderer.

### Platform: SDL3

- PlayStation, Switch and Xbox drivers, hot-plug, and button labels by position,
  which the controller feature names its buttons by.
- Native Wayland without libX11.
- `SDL_GetPrefPath` for saves; `SDL_AudioStream` for output.
- Main callbacks that drive the loop on desktop and Emscripten alike.

### Audio

stb_vorbis (or libvorbis) and a small mixer: 16 voices per sample with
first-idle-else-random stealing, per-voice pitch (44100 down to 22050 for Reflex
Boost), DirectSound pan and attenuation in hundredths of a dB implemented
directly, streamed music with manual fades.
[SDL3_mixer 3.0](https://discourse.libsdl.org/t/announcing-the-sdl-mixer-3-official-release/66567)
is an alternative.

### Why not raylib for the C port

Nearly every raylib workaround in the Python port is raylib fighting D3D8
semantics:

- no render-target stack ([`texture_mode.py`](../src/grim/texture_mode.py));
- alpha test emulated with a discard shader ([`shaders.py`](../src/grim/shaders.py));
- custom blend factors reapplied around every mode switch ([`blend.py`](../src/grim/blend.py));
- `EndDrawing` hijacks F12, worked around by hooking the GLFW key callback
  ([`app.py`](../src/grim/app.py));
- macOS exclusive fullscreen renders into a quarter of the framebuffer;
- the raudio pan law inverted to emulate DirectSound ([`audio_math.py`](../src/grim/audio_math.py));
- `DrawTexturePro` UV collapse under clamp, rotation-origin semantics and
  flipped Y in render textures;
- desktop GLSL 3.3 only, so the web needs ES variants anyway.

The retired Zig port's raylib web target also needed `-sASYNCIFY`. Grim is
already an immediate-mode 2D API, so rlgl adds a translation layer rather than
removing one.
[raylib 6.0](https://newreleases.io/project/github/raysan5/raylib/release/6.0)
can sit on SDL3 for platform code, but then it is mostly SDL3 with extra
constraints.

**Keep raylib for the Python port.** Its problems are solved there, and moving
pyray to SDL3 bindings costs a lot for little gain.

## Plan

1. **Compile all 576 exe files** in [`build.py`](build.py) against the headless
   Grim, and run the state machine through the menus headless. The matrix must
   stay bit-exact.
2. **Grim backend** on SDL3 and GLES3, ported from [`src/grim`](../src/grim).
   Check it with the UI screenshot diff against the Python port and original
   captures.
3. **Sound and platform layer:** mixer, config file, IndexedDB on the web,
   WinInet off.
4. **Emscripten build** with SDL3 main callbacks; assets fetched on first launch
   as the Python port does.
5. **Session policy** from the roadmap: menus freeze the gameplay clock, perk
   picks go through the command seam, replays are recorded.
6. **Product features:** controller layer, letterboxing, the remaining bug
   patches (co-op, HUD and menu entries), ranked upload with WebCrypto
   signatures.

Steps 1–4 give a faithful web Crimsonland. Step 6 is where most of the effort
goes.
