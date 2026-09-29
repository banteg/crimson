from __future__ import annotations

from typing import Annotated

import msgspec

type NonNegativeInt = Annotated[int, msgspec.Meta(ge=0)]
type PlayerCount = Annotated[int, msgspec.Meta(ge=1, le=4)]
type I32 = Annotated[int, msgspec.Meta(ge=-(1 << 31), le=(1 << 31) - 1)]
type NonNegativeI32 = Annotated[int, msgspec.Meta(ge=0, le=(1 << 31) - 1)]
type U32 = Annotated[int, msgspec.Meta(ge=0, le=0xFFFFFFFF)]

__all__ = [
    "I32",
    "U32",
    "NonNegativeI32",
    "NonNegativeInt",
    "PlayerCount",
]
