from __future__ import annotations

from typing import Annotated, TypeAlias

import msgspec

NonNegativeInt: TypeAlias = Annotated[int, msgspec.Meta(ge=0)]
PositiveInt: TypeAlias = Annotated[int, msgspec.Meta(ge=1)]
PlayerCount: TypeAlias = Annotated[int, msgspec.Meta(ge=1, le=4)]
NonNegativeFloat: TypeAlias = Annotated[float, msgspec.Meta(ge=0.0)]
PositiveFloat: TypeAlias = Annotated[float, msgspec.Meta(gt=0.0)]
SignedIndex: TypeAlias = Annotated[int, msgspec.Meta(ge=-1)]

__all__ = [
    "NonNegativeFloat",
    "NonNegativeInt",
    "PlayerCount",
    "PositiveFloat",
    "PositiveInt",
    "SignedIndex",
]
