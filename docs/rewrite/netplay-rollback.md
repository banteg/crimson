---
tags:
  - rewrite
  - multiplayer
  - networking
  - rollback
---

# Netplay (rollback primary)

Rollback netcode is the primary multiplayer path for the rewrite, for both LAN
and internet sessions. Network sessions are room-code based and relay-backed.

## Locked product decisions

- Default netcode mode: `rollback`.
- Legacy mode: `lockstep` (manual pre-match fallback only).
- Topology: UDP client <-> UDP relay (no direct host IP gameplay path).
- Discovery/session: invite-code rooms.
- Local player model: one local player per peer.
- Rollback cap: fixed `8` ticks.
- Input delay default: `1` tick.
- Reconnect timeout default: `15_000` ms.
- Compatibility: relay protocol v5; old LAN/relay compatibility is intentionally broken.

## Runtime surfaces

### CLI

Primary commands in `src/crimson/cli/net.py`:

- `uv run crimson relay serve --bind <ip> --port <port> [--tick-ms <n>]`
- `uv run crimson net host --mode survival|rush|quests --players <1..4> [--quest-level <major.minor>] [--relay-host <ip>] [--relay-port <n>] [--room-code <code>] [--netcode rollback|lockstep]`
- `uv run crimson net join --code <invite> [--relay-host <ip>] [--relay-port <n>]` (rollback)
- `uv run crimson net join --netcode lockstep --host <ip> [--port <n>]` (lockstep fallback)

### Game loop/runtime

- `src/crimson/net/rollback_runtime.py` is the rollback runtime used by default.
- `src/crimson/net/rollback.py` owns input timelines, prediction, mismatch
  tracking, rollback requests, and overflow->resync trigger.
- `src/crimson/net/rollback_snapshot.py` provides snapshot ring storage for
  rollback/reconnect restore workflows.
- `src/crimson/net/lockstep_runtime.py` remains the lockstep fallback
  implementation.
- `src/crimson/game/loop_view.py` selects runtime strategy via `netcode_mode`.

## Relay protocol v5

Implemented in `src/crimson/net/relay_protocol.py` and
`src/crimson/net/relay_reliable.py`.

- Control-plane messages: `client_hello`, `client_welcome`, `room_create`,
  `room_join`, `room_state`, `room_ready`, `room_start`, `peer_disconnect`,
  `relay_error`, `ping`, `pong`.
- Gameplay-plane messages:
  - rollback: `rb_input_sample`, `rb_resync_request`, `rb_resync_begin`,
    `rb_resync_chunk`, `rb_resync_commit`
  - legacy tunnel: `lockstep_state_input_batch`,
    `lockstep_state_tick_frame`, `lockstep_state_control`
- `rb_resync_*` carries `request_id`; begin/commit include snapshot tick and
  sha256 checksum; begin includes codec + compressed/uncompressed size.
- Runtime timeout policy: `LINK_TIMEOUT_MS=5000`, `PING_INTERVAL_MS=250`.
- Reliable control uses seq/ack/resend via `RelayReliableLink`.
- Rollback input batches are mostly unreliable with local resend history.

## Relay service

Implemented in `src/crimson/net/relay_service.py`.

Responsibilities:

- room code allocation and in-memory room registry
- slot assignment + room config enforcement
- heartbeat/timeout handling
- reconnect token issuance and reclaim flow
- room state + room start fan-out
- gameplay packet forwarding by room

## Reconnect and resync policy

- On peer disconnect, match enters paused reconnect window.
- If room fully reconnects before timeout, runtime resumes.
- If timeout elapses, session aborts with `reconnect_timeout`.
- If an input correction arrives older than rollback window, runtime requests
  host resync (`rb_resync_request`) and pauses.
- No automatic mode switching between rollback and lockstep.

## Coverage

Primary tests:

- `tests/test_relay_protocol.py`
- `tests/test_relay_service.py`
- `tests/test_rollback_core.py`
- `tests/test_rollback_resync_v5.py`
- `tests/test_net_runtime_heartbeat.py`
- `tests/test_net_runtime_rollback.py`
- `tests/test_net_runtime_resync.py`
- `tests/test_net_runtime_modes.py`
- `tests/test_net_reconnect.py`
- `tests/test_net_runtime_lockstep_fallback.py`
- `tests/test_net_cli.py`
- `tests/test_net_ui_flow.py`
