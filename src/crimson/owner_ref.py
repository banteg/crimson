from __future__ import annotations

from enum import IntEnum

import msgspec

LOCAL_PLAYER_OWNER_ID = -100


class OwnerKind(IntEnum):
    NONE = 0
    PLAYER = 1
    CREATURE = 2


class OwnerRef(msgspec.Struct, frozen=True):
    kind: OwnerKind
    index: int = 0
    local_host: bool = False

    @classmethod
    def none(cls) -> OwnerRef:
        return cls(kind=OwnerKind.NONE)

    @classmethod
    def from_local_player(cls, index: int) -> OwnerRef:
        return cls(kind=OwnerKind.PLAYER, index=int(index), local_host=True)

    @classmethod
    def from_player(cls, index: int) -> OwnerRef:
        return cls(kind=OwnerKind.PLAYER, index=int(index), local_host=False)

    @classmethod
    def from_creature(cls, index: int) -> OwnerRef:
        return cls(kind=OwnerKind.CREATURE, index=int(index), local_host=False)

    @classmethod
    def from_legacy(cls, owner_id: int) -> OwnerRef:
        owner = int(owner_id)
        if owner == LOCAL_PLAYER_OWNER_ID:
            return cls.from_local_player(0)
        if owner < 0:
            idx = -1 - owner
            if idx >= 0:
                return cls.from_player(idx)
            return cls.none()
        return cls.from_creature(owner)

    def to_legacy(self) -> int:
        if self.kind == OwnerKind.NONE:
            return 0
        if self.kind == OwnerKind.CREATURE:
            return int(self.index)

        if bool(self.local_host) and int(self.index) == 0:
            return LOCAL_PLAYER_OWNER_ID
        return -1 - int(self.index)

    def is_player(self) -> bool:
        return self.kind == OwnerKind.PLAYER

    def player_index(self) -> int | None:
        if self.kind != OwnerKind.PLAYER:
            return None
        return int(self.index)

    def player_index_in_bounds(self, player_count: int) -> int | None:
        idx = self.player_index()
        if idx is None:
            return None
        if 0 <= idx < int(player_count):
            return int(idx)
        return None

    def creature_index(self) -> int | None:
        if self.kind != OwnerKind.CREATURE:
            return None
        return int(self.index)

    def creature_index_in_bounds(self, creature_count: int) -> int | None:
        idx = self.creature_index()
        if idx is None:
            return None
        if 0 <= idx < int(creature_count):
            return int(idx)
        return None

__all__ = [
    "LOCAL_PLAYER_OWNER_ID",
    "OwnerKind",
    "OwnerRef",
]
