---
tags:
  - rewrite
  - multiplayer
  - networking
  - lockstep
---

# LAN lockstep (fallback mode)

Legacy lockstep is retained as a compatibility fallback mode while rollback is
primary for network play.

## Current role

- Not default.
- Selectable manually via advanced netcode selection (`--netcode lockstep`).
- Intended as a pre-match fallback option when rollback is not desired.
- Kept for legacy behavior continuity while rollback remains the main path.

Primary architecture doc:

- [`docs/rewrite/netplay-rollback.md`](netplay-rollback.md)

Protocol note:

- Rollback/relay wire protocol is now v5. Legacy v4 peers are rejected with
  `relay_error` / `client_welcome.reason=protocol_mismatch_v5_required`.

## Runtime surfaces

### CLI

- `uv run crimson net host ... --netcode lockstep`
- `uv run crimson net join ... --netcode lockstep`

### Runtime modules

Lockstep implementations live under `src/crimson/net/lockstep_*`:

- `lockstep_protocol.py`
- `lockstep_lobby.py`
- `lockstep_state.py`
- `lockstep_runtime.py`

## Lockstep protocol contract

Lockstep protocol constants and message contracts are defined in
`src/crimson/net/lockstep_protocol.py`.

- deterministic lockstep tick frame contract
- reliable control channel with resend/ack
- host-authored canonical frame stream
- desync/resync helper messaging

## Policy

- No automatic mid-match switching between rollback and lockstep.
- Manual fallback is selected before match start.
- Rollback remains the product-default mode for new sessions.

## Coverage

Fallback and compatibility tests:

- `tests/test_lan_protocol.py`
- `tests/test_lan_reliable_channel.py`
- `tests/test_lan_lobby_handshake.py`
- `tests/test_lan_lockstep_host.py`
- `tests/test_lan_lockstep_client.py`
- `tests/test_lan_runtime.py`
- `tests/test_lan_cli.py`
- `tests/test_lan_ui_flow.py`
- `tests/test_net_runtime_lockstep_fallback.py`
