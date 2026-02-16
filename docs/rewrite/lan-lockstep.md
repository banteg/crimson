---
tags:
  - rewrite
  - multiplayer
  - networking
  - legacy
---

# LAN lockstep (legacy fallback)

Legacy lockstep is retained as a compatibility fallback mode while rollback is
primary for network play.

Last reviewed: **2026-02-16**

## Current role

- Not default.
- Selectable manually via advanced netcode selection (`--netcode lockstep`).
- Intended as a pre-match fallback option when rollback is not desired.
- Kept for legacy behavior continuity while rollback remains the main path.

Primary architecture doc:

- [`docs/rewrite/netplay-rollback.md`](netplay-rollback.md)

## Runtime surfaces

### CLI

- `uv run crimson net host ... --netcode lockstep`
- `uv run crimson net join ... --netcode lockstep`
- Deprecated wrappers still available for one release cycle:
  - `uv run crimson lan host ...`
  - `uv run crimson lan join ...`

### Runtime modules

Legacy implementations live under `src/crimson/net/legacy_*`:

- `legacy_protocol.py`
- `legacy_lobby.py`
- `legacy_lockstep.py`
- `legacy_runtime.py`

Compatibility re-export modules preserve old imports:

- `src/crimson/net/protocol.py`
- `src/crimson/net/lobby.py`
- `src/crimson/net/lockstep.py`
- `src/crimson/net/runtime.py`

## Legacy protocol contract

Legacy lockstep protocol constants and message contracts are still defined in
`src/crimson/net/legacy_protocol.py`.

- deterministic lockstep tick frame contract
- reliable control channel with resend/ack
- host-authored canonical frame stream
- desync/resync helper messaging

## Policy

- No automatic mid-match switching between rollback and lockstep.
- Manual fallback is selected before match start.
- Rollback remains the product-default mode for new sessions.

## Coverage

Legacy fallback and compatibility tests:

- `tests/test_lan_protocol.py`
- `tests/test_lan_reliable_channel.py`
- `tests/test_lan_lobby_handshake.py`
- `tests/test_lan_lockstep_host.py`
- `tests/test_lan_lockstep_client.py`
- `tests/test_lan_runtime.py`
- `tests/test_lan_cli.py`
- `tests/test_lan_ui_flow.py`
- `tests/test_net_runtime_lockstep_fallback.py`
