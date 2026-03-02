from __future__ import annotations

import msgspec

from crimson.net.lockstep_protocol import LobbySlot, LockstepPacket, PauseState
from crimson.net.relay_protocol import Ping, RelayPacket, RelaySlot
from crimson.net.schema_shared import PacketHeader, SlotState


def _field_names(struct_type: type[msgspec.Struct]) -> list[str]:
    return [field.name for field in msgspec.structs.fields(struct_type)]


def test_slot_state_is_shared_between_lockstep_and_relay() -> None:
    assert issubclass(LobbySlot, SlotState)
    assert issubclass(RelaySlot, SlotState)
    assert _field_names(SlotState) == ["slot_index", "connected", "ready", "is_host", "peer_name"]
    assert _field_names(LobbySlot) == _field_names(SlotState)
    assert _field_names(RelaySlot) == _field_names(SlotState)
    lobby_slot = LobbySlot()
    relay_slot = RelaySlot()
    assert lobby_slot.slot_index == relay_slot.slot_index
    assert lobby_slot.connected == relay_slot.connected
    assert lobby_slot.ready == relay_slot.ready
    assert lobby_slot.is_host == relay_slot.is_host
    assert lobby_slot.peer_name == relay_slot.peer_name


def test_packet_header_is_shared_without_changing_message_defaults() -> None:
    assert issubclass(LockstepPacket, PacketHeader)
    assert issubclass(RelayPacket, PacketHeader)
    assert _field_names(PacketHeader) == ["seq", "ack", "reliable"]
    assert _field_names(LockstepPacket)[:3] == _field_names(PacketHeader)
    assert _field_names(RelayPacket)[:3] == _field_names(PacketHeader)
    assert isinstance(LockstepPacket().message, PauseState)
    assert isinstance(RelayPacket().message, Ping)
