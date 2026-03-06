from __future__ import annotations

import msgspec

from ..replay.checkpoints import ReplayCheckpoint
from .payloads import BuiltinObject, BuiltinValue, to_builtin_object
from .trace import TraceError


def checkpoint_to_channel(checkpoint: ReplayCheckpoint) -> BuiltinObject:
    return to_builtin_object(checkpoint, field="checkpoint")


def channel_to_checkpoint(value: BuiltinValue) -> ReplayCheckpoint:
    try:
        return msgspec.convert(value, type=ReplayCheckpoint)
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise TraceError("invalid checkpoint channel payload") from exc
