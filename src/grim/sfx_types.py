from __future__ import annotations

import msgspec

from .geom import Vec2
from .sfx_map import SfxId


class SfxRequest(msgspec.Struct, frozen=True):
    """A chosen sound and the event's spatial/gain inputs, without device state."""

    sfx_id: SfxId
    position: Vec2 | None = None
    gain: float = 1.0
