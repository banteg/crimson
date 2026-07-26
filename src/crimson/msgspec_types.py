from __future__ import annotations

from typing import Annotated

import msgspec

type NonNegativeInt = Annotated[int, msgspec.Meta(ge=0)]
type PositiveInt = Annotated[int, msgspec.Meta(ge=1)]
type PlayerCount = Annotated[int, msgspec.Meta(ge=1, le=4)]
type NonNegativeFloat = Annotated[float, msgspec.Meta(ge=0.0)]
type PositiveFloat = Annotated[float, msgspec.Meta(gt=0.0)]
type SignedIndex = Annotated[int, msgspec.Meta(ge=-1)]

__all__ = [
    "NonNegativeFloat",
    "NonNegativeInt",
    "PlayerCount",
    "PositiveFloat",
    "PositiveInt",
    "SignedIndex",
]
