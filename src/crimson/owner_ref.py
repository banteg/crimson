from __future__ import annotations

from enum import IntEnum

import msgspec


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
    "OwnerKind",
    "OwnerRef",
]
