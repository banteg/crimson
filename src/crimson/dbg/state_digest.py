from __future__ import annotations

import dataclasses
import hashlib
import struct
from enum import Enum

import msgspec

from grim.rand import CrtRand, RecordingCrand

from ..bonuses.pool import BonusPool
from ..creatures.runtime import CreaturePool
from ..effects import EffectPool, FxQueue, FxQueueRotated, ParticlePool, SpriteEffectPool
from ..persistence.save_status import GameStatus
from ..projectiles.runtime import ProjectilePool, SecondaryProjectilePool
from ..sim.sessions import DeterministicSession

# These pools use ordinary Python objects. Include their complete stored state,
# including inactive entries, allocation cursors and RNG references. New object
# kinds must be admitted explicitly rather than silently omitted by the oracle.
_POOL_TYPES = (
    BonusPool,
    CreaturePool,
    EffectPool,
    FxQueue,
    FxQueueRotated,
    ParticlePool,
    SpriteEffectPool,
    ProjectilePool,
    SecondaryProjectilePool,
)


def _state_value(value: object) -> object:
    if isinstance(value, Enum):
        return _state_value(value.value)
    if value is None or isinstance(value, (bool, int, str, bytes)):
        return value
    if isinstance(value, float):
        # Preserve signed zero and NaN payloads in native slot residue too.
        return ("float64", struct.pack("<d", value))
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, (CrtRand, RecordingCrand)):
        return ("rng", value.state)
    if isinstance(value, GameStatus):
        return _state_value(value.as_data())
    if isinstance(value, (list, tuple)):
        return [_state_value(item) for item in value]
    if isinstance(value, dict):
        items = [(_state_value(key), _state_value(item)) for key, item in value.items()]
        return ("map", sorted(items, key=lambda row: msgspec.msgpack.encode(row[0])))
    if isinstance(value, msgspec.Struct):
        fields = {
            name: _state_value(getattr(value, name))
            for name in value.__struct_fields__
            if not (isinstance(value, DeterministicSession) and name == "last_presentation_plan_ms")
        }
    elif dataclasses.is_dataclass(value) and not isinstance(value, type):
        fields = {field.name: _state_value(getattr(value, field.name)) for field in dataclasses.fields(value)}
    elif isinstance(value, _POOL_TYPES):
        fields = {name: _state_value(item) for name, item in vars(value).items()}
    else:
        raise TypeError(f"unsupported deterministic state component: {type(value).__qualname__}")
    return (type(value).__qualname__, fields)


def session_state_bytes(session: DeterministicSession) -> bytes:
    """Canonical complete session state for same-build port comparisons.

    This is an inspection encoding, not a recoverable snapshot or a wire format.
    Paths, dirty flags, RNG trace sinks and profiling samples are excluded;
    gameplay fields and all pool residue are included automatically.
    """
    return msgspec.msgpack.encode(_state_value(session), order="deterministic")


def session_digest(session: DeterministicSession) -> str:
    return hashlib.sha256(session_state_bytes(session)).hexdigest()
