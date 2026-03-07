from __future__ import annotations

import msgspec

from ..msgspec_types import NonNegativeInt, SignedIndex


class SlotState(msgspec.Struct, forbid_unknown_fields=True):
    slot_index: SignedIndex = -1
    connected: bool = False
    ready: bool = False
    is_host: bool = False
    peer_name: str = ""


class PacketHeader(msgspec.Struct, forbid_unknown_fields=True):
    seq: NonNegativeInt = 0
    ack: NonNegativeInt = 0
    reliable: bool = False


__all__ = ["PacketHeader", "SlotState"]
