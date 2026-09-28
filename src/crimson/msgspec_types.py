from __future__ import annotations

from typing import Annotated

import msgspec

type NonNegativeInt = Annotated[int, msgspec.Meta(ge=0)]
type PlayerCount = Annotated[int, msgspec.Meta(ge=1, le=4)]

__all__ = [
    "NonNegativeInt",
    "PlayerCount",
]
