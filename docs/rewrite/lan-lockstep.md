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

Last reviewed: **2026-02-13**

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

- `uv run crimson lan host --mode survival|rush|quests --players <1..4> [--quest-level <major.minor>] [--bind <ip>] [--port <n>] [--preserve-bugs]`
- `uv run crimson lan join --host <ip> [--port <n>]`

Notes:

- Quest hosting enforces `--quest-level`.
- `lan host` seeds an auto-start host session.
- `lan join` preloads pending join data; mode start continues through in-game flow.

### In-game UI

Implemented in `src/crimson/frontend/panels/lan_session.py` and
`src/crimson/game/loop_view.py`:

- New actions: `open_lan_session`, `start_survival_lan`, `start_rush_lan`,
  `start_quest_lan`.
- Panel supports host/join role, mode, player count, host/bind IP, port, and
  quest level entry.
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
- LAN protocol/reliability/lobby/lockstep/resync core modules
- LAN CLI + pending session routing
- feature-flagged LAN setup panel

Pending for full end-to-end LAN match runtime:

- bind `src/crimson/net/*` transport/poll/send loops into gameplay mode update
  paths for live host/client simulation advancement
- wire pause/resume and resync execution into active match flow
- complete phased enablement (Survival -> Rush -> Quests) behind
  `cv_lanLockstepEnabled`
