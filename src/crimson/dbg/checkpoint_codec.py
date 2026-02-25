from __future__ import annotations

import msgspec

from ..replay.checkpoints import ReplayCheckpoint
from .trace import TraceError


def checkpoint_to_channel(checkpoint: ReplayCheckpoint) -> dict[str, object]:
    value = msgspec.to_builtins(checkpoint)
    if not isinstance(value, dict):
        raise TraceError("checkpoint conversion produced non-dict payload")
    return value


def channel_to_checkpoint(value: object) -> ReplayCheckpoint:
    try:
        return msgspec.convert(value, type=ReplayCheckpoint)
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise TraceError("invalid checkpoint channel payload") from exc

