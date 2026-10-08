# Native and web port

The plan for a playable native and web build of the recovered game, the seam it
ports at, and what each phase has established. Started 2026-10-07; updated as
phases land.

## Summary

The whole recovered game is one wasm32 **game module**: every executable and
Grim source file except a small Windows surface. The port replaces only what
lies below Grim: a Direct3D 8 device, DirectInput, DirectSound and a few Win32
calls, implemented over a small host interface. One C host (SDL3 and an owned
OpenGL renderer) runs the module natively and in the browser.

The module runs two ways. **As the original** (`game_start`, `game_frame`), it
is the 2003 executable: its startup, menus, variable timestep and input, one
frame per host callback. **As a session** (`portable_init`,
`portable_step_many`), it is the verifier: fixed ticks fed a recorded input
tuple, where Grim answers input and time queries exactly as the headless
verifier does and gameplay RNG may only be drawn inside run start and ticks.
Everything the module sends the host returns nothing, so presentation cannot
feed back into either.

Python stays the reference port and the ranked client: it records the `.crd`
replays the leaderboard takes and signs their upload, which the client does
not yet (phase 9).

## Architecture

### The seam is below Grim

The spec first placed the seam at the Grim2D interface, reimplementing its 84
methods over a modern renderer. Compiling the recovered Grim changed that: 156
of its 171 source files build for wasm32 as recovered (through the same
declaration repairs as the executable), and the rest are window, dialog and
device-creation code. The recovered Grim already reproduces the
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
| DirectInput keyboard, mouse and joystick | [`dinput.cpp`](game/dinput.cpp): device state the host delivers each frame; an SDL gamepad is the joystick, laid out as the Logitech Dual Action the game's pad schemes are named for |
| Grim's window procedure and run loop | [`frame.cpp`](game/frame.cpp): one loop pass per host frame; window messages as calls |
| `grim.dll`'s embedded font and splash | [`resources.cpp`](game/resources.cpp) reads them from `grim.dll`; without it, the font from `crimson.paq` and a blank splash, which nothing draws |
| Files, registry, threads, WinInet, DLLs | [`win32.cpp`](game/win32.cpp): Windows paths under the game directory, a registry file, threads that run to completion, offline WinInet, no DLLs |
| DirectSound | [`dsound.cpp`](game/dsound.cpp) mixes the buffers inside the module; the host pulls the mix |
| vorbisfile | [`vorbis.cpp`](game/vorbis.cpp) over stb_vorbis |
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

The host drives the module through exports: a frame, input state, window
events, and `game_audio`, the next frames of the mix. DirectSound's buffers,
play cursors and voice status live in the module, which the recovered audio
code polls to stream music and pick voices; the host only plays what it pulls,
or pulls it at wall-clock pace into nothing when there is no output. So no
output device, a muted or autoplay-locked one, or a failing one can reach the
game: the original's own no-sound path only follows a disabled sound setting.
Voice stealing draws the C library's `rand`, which never touches the gameplay
`crt_rand` stream.

### The tick seam

[`host/game.inc`](host/game.inc) wraps the recovered Grim. During
`portable_init` and `portable_step_many`, every input and time query answers as
the verifier's headless Grim does, and the executable's own session-sensitive
functions (`game_state_set`, the run-down timeline, primary input, play time)
take the verifier's behaviour. Outside those scopes the recovered behaviour
runs. In a headless session, `crt_rand` aborts outside run start and ticks.

Headless, a session sets Grim's own `grim_render_disabled` switch and owns a
device that never becomes ready: the recovered state calls run, and draws stop
inside Grim.

### Runs the client plays

A run the client plays is a verifier session inside the running original
([`host/session.inc`](host/session.inc)). The original's menus start it: where
`game_state_set` sets a run up, the session takes over with a fresh seed, the
player's progress and settings (unlocks, weapon usage, detail, hardcore,
violence, friendly fire, retries) and the original's rules (bugs preserved).
Each pass of the run loop banks wall time and runs the 60 Hz ticks it covers;
each tick's input is built from the player's bindings and scheme as Python's
recorder builds it ([`local_input.py`](../src/crimson/local_input.py)) and is
recorded before the tick runs. A pass that covers no tick draws nothing, and
the host shows the last frame again. Runs are single-player Survival, Rush and
Quests at 1024x768, the resolution the verifier simulates; the rest play as the
original. A fresh configuration is the Python port's: windowed, since the host
owns the window, at 1024x768, with violence on (the original turns it off when
it writes a missing `crimson.cfg`). The main menu leaves out Other Games, 10tons'
catalogue of the time, as the Python port does.

Between ticks the original keeps its screens. The perk menu opens when a tick
opens it, and its choice reaches the run as a command with the next tick.
Escape runs the pause timeline down by the ticks' time, then the pause menu
opens and the run waits, also through its options and controls screens. The
end of the run shows the original's end screen after the verifier's 500 ms
run-down; leaving any other way, quitting included, ends it unfinished and
keeps its recording. The original's frame draws a gameplay random number every
frame: in a run each tick draws it (`portable_step_many`), and between ticks the
frame and the menus draw from a stream of their own. The console stays closed,
since its flag pauses parts of a tick. The recording goes to `replays/` as the
verifier's stream: the 65-word configuration, then each tick's input and
commands ([`checks/replay.py`](checks/replay.py)). A tick takes at most one
perk command, judged by the state it starts from, since a pick can use up the
last perk or kill the player; commands the verifier would refuse (in Rush, once
dead, with no perk left) are dropped, as the original ignores them, and the
perk menu takes one choice per opening.

A tick reads exactly the verifier's state. A run resets the simulation's
globals (the names the verifier's sources and host use) except what the
original loaded or laid out: texture, sound and music handles, the screen
transition, the sprite-sheet cells effects, bonuses and the player draw with,
and the perk prompt's layout (`SESSION_KEEPS` in [`game.py`](game.py)); a name
inside an aggregate the run keeps stays with it. A tick never hit-tests the prompt, as the
verifier lays out none; a click on it opens the perk menu between ticks, as a
command, like the pick key. The settings and progress a tick
reads (the configuration, the status, the corpse-fade cvar, the players' key
codes) are the verifier's, swapped in for each tick; between ticks the
original shows and keeps the player's. What a tick changes carries over: the
counters it advances add to the player's progress, the settings it changes
replace the player's. The verifier's setup assigns its own music ids and
volumes, which only choose and voice tracks; the run plays the original's. The
weapons' sound ids are snapshot fields that hold the original's loaded ids in
a run, and only choose samples.

### Evidence

- [`checks/game_check.py`](checks/game_check.py) runs sessions in the game
  module and the verifier through every gate stream (the 134-run bot corpus
  under both bug policies and the 8 supported recordings) and compares all
  36,343 snapshot fields after every tick; where a run ends, both must refuse
  the next tick. All 142 agree, with the whole executable linked. Fields only
  presentation reads stay out of the comparison: `player_weapon_popup_timer`,
  which the restored HUD counts down, and the weapons' sound ids, which hold
  the original's loaded ids in a run inside it.
- `game_check.py --live <game directory>` runs the same 142 streams back to
  back inside the original booted with its assets, sounds and music, each run
  starting from the state the previous one left, and all agree.
- [`checks/game_session.mjs`](checks/game_session.mjs) plays a Survival run
  through the menus at frame times from 4 to 50 ms (passes with no tick and
  passes with three) and, after every frame, compares the run with the verifier
  replaying the run's own recording; the run must end on the verifier's tick and
  the saved replay must match. Each run has a fresh seed; a failing run names
  its seed, and `--seed` plays it again.
- [`checks/game_boot.mjs`](checks/game_boot.mjs) boots the original from a fresh
  game directory under Node's WASI, clicks through the menus into Survival, and
  requires every texture to load, the menus' music to reach the mix, the run to
  keep drawing, and a lost and regained window to suspend and resume it.

The verifier's hand-set cvars differ from the registered defaults for two
values it never reads: terrain body transparency (verifier 0.8, original 0) and
pad aim distance (verifier 128, original 96; recorded pad aim replaces it).

### Packaging

The native client embeds the module through `wasm2c`, so the simulation keeps
wasm32 layout everywhere. The browser build uses the same host through
Emscripten.

The verifier stays its own artifact. The plan was for it to converge onto the
game module once the client played sessions; measured, the game module
verifies a 21,000-tick run about as fast as the verifier (370 against 300 ms
in Node) but is sixteen times larger (1.8 MB against 109 KB gzipped), needs
WASI and host imports, and would change bytes whenever a menu or a texture
loader does. The import-free verifier remains the trust anchor, and every
client build is held to it instead: CI runs every check above, booting the
original on the distributed files ([Assets](#assets)) and playing the session
check on a seed whose run picks perks and pauses.

### Assets

The client reads a game directory: `crimson.paq`, `sfx.paq` and the `music`
folder, and `grim.dll` when it is there (the configuration files appear on first
launch). The executable
asks for music as `music\<name>.ogg`, which no PAQ entry matches, so it plays
the loose files, as the GOG release ships them; the in-game tunes are whatever
`music\game_tunes.txt` adds. Nothing runs `grim.dll`: Grim is in the module,
and the DLL only holds two RCDATA images Grim's device loads, its default font
and a splash it never draws. Both `crimson.paq` releases carry the same font as
`load/default_font_courier.tga`, which the module reads when there is no
`grim.dll` ([`resources.cpp`](game/resources.cpp)); the executable sets Grim's
pack only after its device is up, so it reads the file itself.

The project distributes the files from its asset host, by 10tons' permission:
`sfx.paq` as released, `crimson.paq` repacked with the
uncompressed art Tero sent (forward-slash names, each image in its own format,
`game/alien.tga` where the executable asks for `game\alien.jaz`), and
`music.paq` with the release's music and the official music addon, whose
`music/game_tunes.txt` adds the addon tunes. Grim finds a PAQ entry by its exact
name and decodes it by the name's extension, so the module asks for the stored
name first ([`repack.cpp`](game/repack.cpp)); the release's `crimson.paq`
resolves every name to itself. The clients unpack `music.paq` into `music/`.
[`checks/game_files.py`](checks/game_files.py) lays out a game directory from
the asset host, which CI uses for the checks that boot the original.

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
crimson-core/build/app/crimson [game directory]
```

It needs wabt's `wasm2c`, SDL3 and the original game files. Without a
directory the client uses the folder chosen last time, or asks for the one
Crimsonland is installed in. `--package` lays out what ships in `build/dist`:
a macOS app bundle or a Linux folder carrying SDL3, or the web page's files;
[`client.yml`](../.github/workflows/client.yml) builds all three on every
change; nothing yet runs the packaged executables, and the checks above run the
module before `wasm2c`.

For unattended runs, `CRIMSON_CAPTURE=<dir>` with `CRIMSON_CAPTURE_FRAMES=n,...`
saves those frames' back buffers and quits, and `CRIMSON_INPUT` scripts the
mouse and keys; such a run's clock moves 16 ms a frame, so scripted input lands
on the same frames (a run's seed still differs)
([`client/main.cpp`](client/main.cpp)).

## Running the web client

```sh
uv run python crimson-core/client/build.py --target web   # Emscripten, SDL3 port
```

`build/web/index.html` runs the same host on WebGL2. The game directory is
`/game` in IndexedDB: on first launch the page fetches the game files from
`?assets=<url>` (default `game/` beside the page) with a progress bar; when that
fails, it retries or takes the player's own game folder, either layout; and settings, saves and
high scores sync back a few seconds after the game writes them, when the tab is
hidden, and when the game quits ([`client/web/shell.html`](client/web/shell.html)).
One tab at a time owns the directory (a Web Lock), since IndexedDB takes each
sync as the whole tree and a stale tab would write over newer saves; another
tab's Play here asks the owner to save and reload, and takes the lock from one
that does not answer, which then stops saving. As in the
original, settings changed in the options reach the disk when the game quits.
It needs a secure context (HTTPS or localhost) for the lock, and no threads, so
no cross-origin isolation. A fullscreen icon shows when the pointer reaches its
corner, holding Escape for the game where the browser allows it. The page wears
the site's font and game buttons (`service/public/game.css`).

crimson.land serves the page at [`/play/`](https://crimson.land/play/): the
site's Worker answers `/play/game/<file>` from the asset bucket, same-origin,
for the three distributed files only ([`service/src/index.ts`](../service/src/index.ts)),
and `npm run play` in `service` stages the packaged web build for deploy.

## Plan

| Phase | Delivers | State |
| --- | --- | --- |
| 1. Game module | Recovered Grim and presentation in wasm32; sessions match the verifier on all gate streams | Done ([#550](https://github.com/banteg/crimson/pull/550)) |
| 2. Native client | The whole executable in the module; SDL3/OpenGL host over `wasm2c`; the original game boots, menus and runs play | Done ([#552](https://github.com/banteg/crimson/pull/552)) |
| 3. Web client | The same host through Emscripten; game files in IndexedDB | Done ([#553](https://github.com/banteg/crimson/pull/553)) |
| 4. Audio | DirectSound mixed in the module, vorbisfile over stb_vorbis; the host plays the pulled mix | Done ([#554](https://github.com/banteg/crimson/pull/554)) |
| 5. Sessions in the client | Gameplay as fixed ticks fed recorded input; perk picks as commands; replays; the client artifact passes the gates with the game files and audio loaded | Done ([#555](https://github.com/banteg/crimson/pull/555)) |
| 6. Verifier convergence | Dropped: the verifier stays its own artifact and holds every client build to it ([Packaging](#packaging)) | |
| 7. Product parity | Gamepads as the original's joystick; the web client takes the player's own game folder | Done ([#556](https://github.com/banteg/crimson/pull/556)) |
| 8. Distribution | CI builds and packages the web client, a macOS app and a Linux folder; the native client finds the game folder; next, a Windows host (the WASI layer is POSIX) and signing | Done ([#557](https://github.com/banteg/crimson/pull/557)); crimson.land/play hosts the web client with the distributed files |
| 9. Ranked play from the client | `.crd` replays, the leaderboard's signed upload, replay browsing | |

## Acceptance gates

| Gate | Evidence required |
| --- | --- |
| Simulation | Every gate stream through each release artifact agrees with the verifier on every snapshot field after every tick. |
| Session | Identical input and commands at 30, 60 and 144 Hz display rates, including frames with zero or several ticks, pauses, perk and menu transitions, restarts and tab suspension, give identical state and results. |
| Audio | Identical simulation results with real audio, a null sink, muting, autoplay lock, voice saturation and device failure. |
| Graphics | Captures of terrain persistence, corpse and decal bakes, alpha threshold, blend factors, write masks, fonts, texture edges and gamma against the original, with documented tolerances. |
| Persistence | Saves survive relaunch and reload; a failed asset or storage operation is visible and never changes a ranked run's setup. |
