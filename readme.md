# Crimsonland, rebuilt

[![1.9.93](https://decomp.dev/banteg/crimson.svg?mode=shield&measure=code&category=game&label=1.9.93)](https://decomp.dev/banteg/crimson?category=game)
[![1.9.8](https://decomp.dev/banteg/crimson/1.9.8.svg?mode=shield&measure=code&category=game&label=1.9.8)](https://decomp.dev/banteg/crimson/1.9.8?category=game)
[![1.4.0](https://decomp.dev/banteg/crimson/1.4.0.svg?mode=shield&measure=code&category=game&label=1.4.0)](https://decomp.dev/banteg/crimson/1.4.0?category=game)
[![1.3.0](https://decomp.dev/banteg/crimson/1.3.0.svg?mode=shield&measure=code&category=game&label=1.3.0)](https://decomp.dev/banteg/crimson/1.3.0?category=game)
[![1.0.2](https://decomp.dev/banteg/crimson/1.0.2.svg?mode=shield&measure=code&category=game&label=1.0.2)](https://decomp.dev/banteg/crimson/1.0.2?category=game)

[Crimsonland](https://en.wikipedia.org/wiki/Crimsonland) (2003), as its 1.9.93 GOG "Crimsonland Classic" release (2011), rebuilt twice:

- **A matching decompilation**: C/C++ source that Visual C++ 6 compiles back into the original `crimsonland.exe` and `grim.dll`, instruction for instruction. Compiled to WebAssembly, it plays the original game in your browser.
- **A reimplementation** in Python and raylib that matches the original's timings, random rolls, float32 rounding and quirks tick by tick, and adds what a modern release needs.

[Play in your browser](https://crimson.land/play/) · [Leaderboard](https://crimson.land) · [The full story](https://banteg.xyz/posts/crimsonland/) · [Docs](https://crimson.banteg.xyz/) · [Changelog](CHANGELOG.md) · [Telegram group](https://t.me/+pG-Ow90lt28zMWFi)

## Play

**[crimson.land/play](https://crimson.land/play/)** is the original game, built from the recovered source. There is nothing to install: it downloads the game files on first visit, keeps your saves in the browser, and plays with a keyboard and mouse or a gamepad. The original's [documented bugs](https://crimson.banteg.xyz/rewrite/original-bugs/) are fixed, and the Ranked box in the Play Game menu enters runs on the leaderboard. **Play co-op** gives you an invite link: send it to a friend and play together from your own browsers.

**The Python port** plays the same game with more room around it: any resolution with borderless fullscreen, local co-op for up to four players on their own controllers, the original bugs back on request with `--preserve-bugs`, and a `crimson` CLI for replays and quests. Install [uv](https://docs.astral.sh/uv/getting-started/installation/), then:

```bash
uvx crimsonland@latest
```

Its [player guide](pypi.md) covers controls, options and commands.

**A native desktop client** runs the browser build over SDL3 on macOS and Linux ([build notes](crimson-core/PORT.md#running-the-native-client)).

The [feature matrix](https://crimson.banteg.xyz/rewrite/feature-matrix/) compares the three. The original Crimsonland Classic assets are distributed with permission from 10tons, and every client downloads them on first launch.

## Beyond the original

- **Sharper art.** The original shipped its textures as JAZ files, JPEG color with a separate alpha channel. The game files every client downloads carry the uncompressed source art from 10tons instead, free of JPEG artifacts, wherever it matches what shipped.
- **Deterministic runs.** The simulation steps at a fixed 60 Hz from a seed and the recorded inputs, so a run plays out the same way every time, on every client.
- **Online co-op.** The original's two-player mode, over the internet: one player opens a room, the other follows the invite link, and both play Survival or any quest from their own browsers. Rollback netcode keeps each player's aim responsive under lag, and a relay steps in when a direct connection can't be made. See the [network co-op specification](https://crimson.banteg.xyz/rewrite/network-coop/).
- **Replays.** Every run is recorded. Watch any of them from the high score screen or a link, seek anywhere, and with the Python port, verify one tick by tick or render it to 60 fps video.
- **A verified leaderboard.** [crimson.land](https://crimson.land) ranks Survival and every quest, normal and hardcore, for one player and for online co-op pairs. A score is a whole run, and the server replays it on the recovered original code before it counts. There is no sign-up: each client makes a [key](https://crimson.banteg.xyz/rewrite/leaderboard-identity/) on first launch. Bots and tool-assisted runs are welcome on [their own board](https://crimson.banteg.xyz/rewrite/bots/).
- **Custom quests.** Crimsonland now comes with a Crimsonlang. Write a quest in [it](https://crimson.banteg.xyz/formats/quest-dsl/), play it with `crimson quest play`, and publish it to get its own page and leaderboard on [crimson.land/custom](https://crimson.land/custom). An LLM can write one from [a single-file spec](https://crimson.land/custom/llm.txt).

## Inside

| Directory | What it holds |
| --- | --- |
| [`decomp/`](decomp/README.md) | the recovered C/C++ source, for every build we study |
| [`src/`](src) | the Python port: game logic in `crimson/`, the engine layer in `grim/` |
| [`crimson-core/`](crimson-core/README.md) | the recovered source built to WebAssembly: the leaderboard's replay verifier, and the whole game behind the browser and native clients |
| [`service/`](service) | crimson.land: the leaderboard, replay verification and the site |
| [`crimson-re/`](crimson-re) | the matching, native link and debugging tools |
| [`docs/`](docs/index.md) | game mechanics, file formats and the reverse engineering, published at [crimson.banteg.xyz](https://crimson.banteg.xyz/) |

The two rebuilds keep each other honest. The Python port settles open questions against the original code running under an emulator, and CI requires the recovered source to play every recorded run exactly as the port does, under both the original rules and the fixed ones.

## Decompilation

The [matching decompilation](decomp/README.md) of 1.9.93 is complete: every game and engine function comes from recovered source, with every reference checked. Bundled third-party libraries (D3DX8, the MSVC runtime, the image and audio codecs) keep their upstream provenance and are not counted.

The same source tree builds other releases, each with its own compiler profile and `CL_BUILD` define, and [decomp.dev](https://decomp.dev/banteg/crimson) tracks each from its own evidence:

| Build | Released | Edition |
| --- | --- | --- |
| 1.9.93 | 2011 | GOG Crimsonland Classic, the canonical build |
| 1.9.8 | 2003 | shareware, measured from the 1.9 sources |
| 1.4.0, 1.3.0, 1.0.2 | 2002 | freeware |

[builds.json](decomp/builds.json) pins and maps more builds than are reported.

## Developing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the project layout, the reverse-engineering and parity workflow, and the checks to run.

## Legal

This project is an independent reverse engineering and reimplementation effort for preservation, research, and compatibility. Original Crimsonland Classic assets are distributed with permission from 10tons; the game code and reimplementation remain independent.
