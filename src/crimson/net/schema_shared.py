from __future__ import annotations

import msgspec


class SlotState(msgspec.Struct, forbid_unknown_fields=True):
    slot_index: int = -1
    connected: bool = False
    ready: bool = False
    is_host: bool = False
    peer_name: str = ""


class PacketHeader(msgspec.Struct, forbid_unknown_fields=True):
    seq: int = 0
    ack: int = 0
    reliable: bool = False


__all__ = ["PacketHeader", "SlotState"]
