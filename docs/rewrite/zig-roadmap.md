---
tags:
  - rewrite
  - parity
  - zig
---

# Zig port roadmap (`crimson-zig/`)

This page scopes the remaining work to move `crimson-zig/` from its current
state, where replay/runtime tooling is the strongest surface, toward the actual
goal: a full native Zig port of Crimson systems, content, and product surfaces.

Last reviewed: **2026-04-10**

## Current baseline

Today the Zig tree has three clearly real foundations:

- deterministic runtime/simulation modules for the replay-supported modes,
- replay/tooling surfaces (`replay verify`, `replay info`, CDT traces),
- codec and packaging work (`paq`, `jaz`, `crimson.cfg`, `game.cfg`).

It also has two intentionally early placeholders:

- native window bootstrap:
  [`crimson-zig/src/window_main.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_main.zig)
  now boots a simple desktop menu -> survival run -> results slice with
  primitive gameplay rendering plus archive-backed menu/bootstrap asset loading,
- wasm runtime ABI:
  [`crimson-zig/src/wasm_exports.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/wasm_exports.zig)
  now executes byte-input replay verify calls, but still exposes only a narrow
  replay-oriented surface.

And the CLI is still narrow:

- [`crimson-zig/src/cli.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/cli.zig)
  exposes only `replay verify` and `replay info`.

That means the remaining scope is not one backlog. It is at least four distinct
programs:

1. finish the deterministic gameplay/runtime core,
2. turn that runtime into a live playable application shell,
3. port the asset/render/audio/UI stack,
4. widen platform and tooling surfaces beyond replay-only entrypoints.

## Scope by workstream

### 1. Core deterministic sim parity

This is the closest workstream to the current Zig tree.

Remaining work:

- Eliminate runtime bail-outs that still report unported gameplay branches.
  - weapon fire fallbacks:
    [`crimson-zig/src/runtime/weapons.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/weapons.zig)
  - creature template fallbacks:
    [`crimson-zig/src/runtime/creatures.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/creatures.zig)
  - perk/bonus apply fallbacks surfaced through replay event application:
    [`crimson-zig/src/runtime/perks.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/perks.zig),
    [`crimson-zig/src/runtime/bonuses.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/bonuses.zig),
    [`crimson-zig/src/runtime/replay/events.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/replay/events.zig)
- Expand supported gameplay modes beyond the current replay-centered
  Survival/Rush/Quest fast path.
  - Tutorial, Typ-o, and demo flows still need true Zig session/runtime support,
    not just “unsupported” rejection paths.
- Widen replay envelope support where the native CLI still rejects inputs.
  - older rulesets except preserve-bugs envelopes,
  - event kinds/bootstrap kinds that are not yet accepted by
    [`crimson-zig/src/replay_codec.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/replay_codec.zig)
    and
    [`crimson-zig/src/verify_native.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/verify_native.zig)
- Keep pulling the Zig runtime shape toward the Python reference architecture.
  - current progress: shared session shell +
    explicit mode builders in
    [`crimson-zig/src/runtime/session.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/session.zig)
    and
    [`crimson-zig/src/runtime/session_builders.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/runtime/session_builders.zig)
  - remaining: more complete mode-specific hooks and a less replay-specific
    deterministic step boundary.

Definition of done for this workstream:

- replay/runtime core can execute the full supported ruleset set without
  “not yet ported” exits on ordinary captures,
- non-replay deterministic sessions exist for all gameplay modes we intend to
  ship in Zig,
- differential capture tooling shows stable parity across a broader corpus than
  the current replay acceptance set.

### 2. Live world runtime shell

The Zig runtime can simulate, but it does not yet own a real live game shell.
Python still owns the concepts that turn a deterministic session into an actual
running game product.

Remaining work:

- Introduce a Zig `World` / live-run shell that owns:
  - active players/creatures/projectiles/bonuses/effects,
  - mode/session lifecycle,
  - frame timing and input ingestion,
  - save/status plumbing,
  - audio/render-facing event boundaries.
- Mirror the Python split between:
  - deterministic session stepping,
  - presentation planning,
  - mode orchestration,
  - boot/menu/game transitions.
- Separate “headless replay runner” concerns from “live game runner” concerns so
  replay becomes a driver over the same world/session code, not its parent.

Closest Python references:

- [`src/crimson/sim/sessions.py`](/Users/banteg/dev/banteg/crimson/src/crimson/sim/sessions.py)
- [`src/crimson/sim/session_builders.py`](/Users/banteg/dev/banteg/crimson/src/crimson/sim/session_builders.py)
- [`src/crimson/game/runtime.py`](/Users/banteg/dev/banteg/crimson/src/crimson/game/runtime.py)
- [`src/crimson/game/loop_view.py`](/Users/banteg/dev/banteg/crimson/src/crimson/game/loop_view.py)

Definition of done for this workstream:

- Zig can boot a gameplay session natively from config/status/input without going
  through replay artifacts,
- replay, sandbox, and live game flows share the same lower-level world/session
  machinery.

### 3. Assets, rendering, and presentation

This is one of the biggest missing chunks. The Zig tree has codec foundations and
placeholder window targets, but not a real presentation pipeline.

Remaining work:

- Convert newly loaded archive textures into renderer-usable asset objects.
  - current progress:
    [`crimson-zig/src/window_assets.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_assets.zig)
    now loads `crimson.paq`, normalizes entry paths, expands JAZ alpha into
    RGBA textures, and supports `.tga` / `.jpg` / `.jpeg` image assets plus
    `load/smallFnt.dat`
  - remaining: sprite atlas/frame metadata, terrain materials, font builders,
    and broader non-window consumers of that asset layer
- Port the terrain renderer and decal/effects presentation model.
- Port gameplay rendering:
  - players,
  - creatures,
  - primary/secondary projectiles,
  - pickups/bonuses,
  - muzzle flashes, blood, corpse/freezer FX, shock/fire/nuke overlays.
- Port HUD and in-game overlays:
  - health/ammo/xp,
  - perk menus,
  - quest/tutorial overlays,
  - game over / results / high score entry.
- Replace the current placeholder window target with a real renderer loop.

Current evidence that this workstream is still early:

- the desktop slice still uses primitive shapes/text for live gameplay instead
  of the real asset stack:
  [`crimson-zig/src/window_main.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_main.zig)
- current asset use is shallow: boot/menu surfaces consume textures, but the
  world renderer, terrain pipeline, HUD widgets, and product UI still do not.

Definition of done for this workstream:

- `zig build run-window` becomes a real playable/rendered app surface,
- asset loading and render output are no longer stub/placeholder-level.

### 4. Boot flow, menus, and product UI

The Python rewrite already owns a large amount of non-gameplay product behavior.
Almost none of that is present in Zig yet.

Remaining work:

- Boot stages:
  splash, company logos, intro/theme handoff, config initialization.
- Main menu and panel system:
  Play Game, Options, Stats, Credits, Mods-shell, panel transitions.
- Quest select, demo/attract flow, and trial/purchase shell behavior where still
  in scope.
- High score entry/results/game over flows.
- Debug views/sandboxes that are currently useful in Python development.

Closest Python references:

- [`src/crimson/screens/`](/Users/banteg/dev/banteg/crimson/src/crimson/screens)
- [`src/crimson/ui/`](/Users/banteg/dev/banteg/crimson/src/crimson/ui)
- [`src/crimson/game/`](/Users/banteg/dev/banteg/crimson/src/crimson/game)

Definition of done for this workstream:

- Zig has a native boot-to-menu-to-gameplay-to-results loop,
- the replay CLI is no longer the dominant user-facing story of the workspace.

### 5. Audio

Audio now has a real desktop/runtime foothold, but it is not done.

Current progress:

- [`crimson-zig/src/audio/audio.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/audio/audio.zig),
  [`crimson-zig/src/audio/music.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/audio/music.zig),
  [`crimson-zig/src/audio/sfx.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/audio/sfx.zig),
  and
  [`crimson-zig/src/audio/live_audio.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/audio/live_audio.zig)
  now mirror the Python split between device/audio orchestration, music state,
  sfx state, and gameplay/menu routing.
- `music.paq`, `sfx.paq`, `music/game_tunes.txt`, and `crimson.cfg` are now
  consumed by the desktop Zig slice.
- the desktop app now has native intro/menu music, first-hit game-tune
  triggering, cfg-driven volume/enable behavior, and gameplay/menu/perk ui sfx.

Remaining work:

- widen gameplay event parity beyond the current desktop slice:
  - creature pain/death/attack sfx,
  - bonus/perk-triggered sfx outside the currently surfaced frame events,
  - fuller quest/tutorial/demo audio routing.
- port the remaining product-shell audio behavior:
  - panels/options/high-score entry/results flows,
  - pause/game over/victory transition muting details,
  - console-driven tune loading commands on the native shell side.
- validate audio parity more deeply against the Python/native reference:
  - game-tune queue mutation,
  - per-mode music behavior,
  - any remaining edge cases around exclusive fading and reflex pitch scaling.

Closest Python references:

- [`src/grim/audio.py`](/Users/banteg/dev/banteg/crimson/src/grim/audio.py)
- [`src/grim/music.py`](/Users/banteg/dev/banteg/crimson/src/grim/music.py)
- [`src/crimson/audio_router.py`](/Users/banteg/dev/banteg/crimson/src/crimson/audio_router.py)

Definition of done for this workstream:

- gameplay and menu audio are native in Zig,
- audio-triggered parity checks are part of live-run validation, not only replay
  summary validation.

### 6. Persistence, config, and local product data

The Zig tree has important codec groundwork here, but not the full application
integration.

Current progress:

- [`crimson-zig/src/app_runtime.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/app_runtime.zig)
  now gives the desktop slice a native owner for runtime-dir `crimson.cfg` and
  `game.cfg`.
- Missing `crimson.cfg` / `game.cfg` files are now created in Zig using the
  existing codecs and Python-matching defaults.
- [`crimson-zig/src/window_main.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/window_main.zig)
  now reads `crimson.cfg` for current window/audio/gameplay defaults and writes
  back `game.cfg` play counters, playtime, unlock indices, and weapon-usage
  state from live runs.

Remaining work:

- widen beyond the current Survival desktop slice:
  Rush/Quest/Tutorial/Typ-o save semantics, quest counters, highscores,
  and broader state ownership,
- support in-product config editing rather than config-as-fixture only,
- expose useful CLI/admin surfaces for inspecting and repairing local state.

Current foundations:

- [`crimson-zig/src/formats/crimson_cfg.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/formats/crimson_cfg.zig)
- [`crimson-zig/src/formats/game_cfg.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/formats/game_cfg.zig)

Definition of done for this workstream:

- a Zig player can boot, play, unlock, save, and re-open with native state
  persistence.

### 7. Wasm and platform embedding

The build targets exist, but the runtime surface is still thin.

Remaining work:

- widen the ABI beyond replay-only behavior,
- decide whether browser/web-worker embedding targets:
  - replay verification,
  - inspector/debug UI,
  - or a playable web build.
- reconcile the freestanding ABI target with the emscripten/raylib web target so
  they point at the same long-term product story.

Current evidence:

- [`crimson-zig/src/wasm_exports.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/src/wasm_exports.zig)
- [`crimson-zig/build.zig`](/Users/banteg/dev/banteg/crimson/crimson-zig/build.zig)

Definition of done for this workstream:

- wasm exports are useful runtime APIs, not an error-reporting shim.

### 8. Networking

This is explicitly later-stage work, but it belongs in full-port scoping.

Remaining work:

- decide whether Zig will eventually own rollback and/or lockstep runtime,
- if yes, port:
  - session settings,
  - transport/protocol layers,
  - rollback state snapshots/resync,
  - relay integration,
  - network UI/lobby/product flows.

Closest Python references:

- [`src/crimson/net/`](/Users/banteg/dev/banteg/crimson/src/crimson/net)

Definition of done for this workstream:

- either networking is declared intentionally out of near-term Zig scope, or a
  concrete port plan exists with live protocol/runtime coverage.

## Suggested staging

This is the sequencing that best matches the current state of the Zig tree.

### Phase 1: finish the runtime core

- remove unsupported replay/runtime branches,
- add full mode session builders/hooks for Tutorial/Typ-o/demo where in scope,
- widen replay acceptance and differential coverage.

### Phase 2: make Zig able to run a live gameplay session

- native config/status boot,
- live input ingestion,
- world/session lifecycle outside replay,
- non-placeholder window loop with gameplay stepping.

### Phase 3: port presentation and audio

- asset loading,
- terrain/sprite/effects rendering,
- HUD/perk/menu overlays,
- music/sfx routing.

### Phase 4: port the product shell

- boot/logo/menu/panels/results/highscore flows,
- debug views and developer tooling surfaces,
- persistence integrated end to end.

### Phase 5: widen platform targets

- useful wasm runtime ABI,
- web embedding strategy,
- optional network/runtime ownership expansion.

## Short version

The Zig port is still early because it has only completed the lowest and most
deterministic slice of the stack well: replay/runtime core + codecs.

The largest remaining work is not “more verifier fixes.” It is:

1. finishing unsupported gameplay branches inside the runtime,
2. building a true live game shell around that runtime,
3. porting rendering/audio/UI/persistence,
4. deciding how far the Zig tree will go on wasm and networking.

If we want the next few PRs to have the highest leverage, they should keep
moving the tree in this order:

1. replay/runtime parity closures,
2. live session startup,
3. real renderer/audio integration,
4. menu/product surfaces.
