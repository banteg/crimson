---
tags:
  - rewrite
  - multiplayer
  - networking
---

# LAN lockstep (rewrite)

Deterministic LAN lockstep for the rewrite is implemented as a host-relay model
over UDP with replay-compatible input frames and host-authoritative recovery.
This page tracks the design contracts and current rollout status.

Last reviewed: **2026-02-14**

## Locked product decisions

- Modes: Survival, Rush, Quests.
- Topology: host relay star; host is always slot/player `0`.
- Transport: UDP with app-level reliability for control messages.
- Input delay: fixed `2` ticks.
- Join policy: lobby-only joins (no mid-run join).
- Discovery: direct `IP:port` only (no broadcast/NAT traversal).
- Desync policy: pause + host-driven resync.
- Compatibility gate: exact `protocol_version` and `build_id`.
- Rollout: feature-flagged in UI, CLI available for bring-up/testing.

## Runtime surfaces

### CLI

Implemented in `src/crimson/cli.py`:

- `uv run crimson lan host --mode survival|rush|quests --players <1..4> [--quest-level <major.minor>] [--bind <ip>] [--port <n>] [--debug]`
- `uv run crimson lan join --host <ip> [--port <n>] [--debug]`

Notes:

- Quest hosting enforces `--quest-level`.
- LAN sessions force `preserve_bugs=0` to keep simulation rules consistent across peers.
- `lan host` starts in a LAN lobby and begins the match automatically once all
  peers are connected + ready.
- `lan join` starts in a LAN lobby and auto-readies when accepted by the host.
- `--host localhost` is supported (resolved to IPv4).
- LAN CLI sessions now emit per-process trace logs under
  `<base-dir>/logs/lan/` (separate host/client files, filename includes role
  and pid) and print the chosen log path on startup.

### In-game UI

Implemented in `src/crimson/frontend/panels/lan_session.py` and
`src/crimson/game/loop_view.py`:

- New actions: `open_lan_session`, `start_survival_lan`, `start_rush_lan`,
  `start_quest_lan`.
- Panel supports host/join role, mode, player count, host/bind IP, port, and
  quest level entry.
- Lobby wait/start panel implemented in `src/crimson/frontend/panels/lan_lobby.py`.
- UI entry is gated behind console cvar `cv_lanLockstepEnabled` (default `0`).

## Network package

Core LAN modules live under `src/crimson/net/`:

- `protocol.py`: msgpack message schema and constants.
- `transport.py`: non-blocking UDP socket wrapper.
- `reliable.py`: per-peer seq/ack/resend/de-dup logic.
- `lobby.py`: host/client handshake, slot assignment, ready barrier.
- `lockstep.py`: host/client lockstep frame state machines.
- `resync.py`: replay/checkpoint bundle chunking + assembly.
- `adapter.py`: host/client adapter wrappers and resync-failure tracking.
- `runtime.py`: lobby + transport driver integrated into the main game loop.

## Protocol contract

Authoritative constants in `src/crimson/net/protocol.py`:

- `PROTOCOL_VERSION = 1`
- `DEFAULT_PORT = 31993`
- `TICK_RATE = 60`
- `INPUT_DELAY_TICKS = 2`
- `MAX_PLAYERS = 4`
- `RELIABLE_RESEND_MS = 40`
- `LINK_TIMEOUT_MS = 1000`
- `INPUT_STALL_TIMEOUT_MS = 250`
- `STATE_HASH_PERIOD_TICKS = 120`

Message encoding is `msgspec.msgpack`.

Reliable message kinds:

- `hello`, `welcome`, `lobby_state`, `ready`, `match_start`
- `tick_frame`, `pause_state`
- `desync_notice`
- `resync_begin`, `resync_chunk`, `resync_commit`
- `disconnect`

Unreliable message kind:

- `input_batch`

Compatibility/build gate:

- handshake requires exact `protocol_version` and exact `build_id` match.
- `build_id` uses `git rev-parse --short=12 HEAD` when available, else
  `crimson.__version__`.

Input wire contract:

- uses replay-compatible packed input payloads
  (`[move_x, move_y, [aim_x, aim_y], flags]`).

## Deterministic prerequisite for quests

Quest mode now has deterministic session/replay support aligned with
Survival/Rush:

- `QuestDeterministicSession` and `QuestDeterministicSessionTick` in
  `src/crimson/sim/sessions.py`.
- `run_quest_replay` in `src/crimson/sim/runners/quest.py`.
- Quest mode loop uses `FixedStepClock(tick_rate=60)` in
  `src/crimson/modes/quest_mode.py`.

This is required for deterministic lockstep/resync rebuild paths in Quests.

## Test coverage

LAN and quest-determinism coverage is tracked by:

- `tests/test_quest_deterministic_session.py`
- `tests/test_lan_protocol.py`
- `tests/test_lan_reliable_channel.py`
- `tests/test_lan_lobby_handshake.py`
- `tests/test_lan_lockstep_host.py`
- `tests/test_lan_lockstep_client.py`
- `tests/test_lan_desync_resync.py`
- `tests/test_lan_cli.py`
- `tests/test_lan_ui_flow.py`
- plus parity/wiring updates in existing deterministic and multiplayer tests.

## Rollout status

Implemented now:

- deterministic quest session prerequisite
- LAN protocol/reliability/lobby/lockstep core modules
- LAN runtime driver (transport + lobby + tick-frame relay)
- Survival/Rush/Quests mode integration (lockstep tick frames drive sim ticks)
- host-only replay/checkpoints for LAN sessions
- LAN CLI + feature-flagged setup UI + lobby view
- debug HUD lines in-game when `--debug` is enabled

Not yet implemented / limitations:

- perk menu ownership + deterministic replication (currently disabled in LAN)
- desync detection + host-driven resync (resync chunking exists, not wired end-to-end)
- phased enablement (Survival -> Rush -> Quests) behind `cv_lanLockstepEnabled`

## Manual testing

### Localhost (single machine, two processes)

1. Choose a runtime directory (so logs are easy to find):

   - `export CRIMSON_RUNTIME_DIR=/tmp/crimson-lan`

2. Terminal A (host):

   - `uv run crimson lan host --mode survival --players 2 --debug`

3. Terminal B (client):

   - `uv run crimson lan join --host 127.0.0.1 --debug`

4. Expected behavior:

   - both processes enter the LAN lobby screen first
   - host shows `Connected peers: 1/2` then `2/2`
   - match starts automatically once both peers are connected/ready
   - in-game debug HUD shows `lan:` and `net(...)` / `lockstep(...)` lines

5. Inspect logs:

   - `/tmp/crimson-lan/logs/lan/`

### Two machines on the same LAN

1. On the host machine:

   - `uv run crimson lan host --mode survival --players 2 --port 31993`

2. Find the host LAN IP (for example `192.168.x.y`) and join from the client:

   - `uv run crimson lan join --host <host-ip> --port 31993`
