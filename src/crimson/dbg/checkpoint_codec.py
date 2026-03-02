from __future__ import annotations

from typing import cast

import msgspec

from ..replay.checkpoints import ReplayCheckpoint
from .trace import TraceError


def checkpoint_to_channel(checkpoint: ReplayCheckpoint) -> dict[str, object]:
    return cast("dict[str, object]", msgspec.to_builtins(checkpoint))


def channel_to_checkpoint(value: object) -> ReplayCheckpoint:
    try:
        return msgspec.convert(value, type=ReplayCheckpoint)
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise TraceError("invalid checkpoint channel payload") from exc
