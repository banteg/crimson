from __future__ import annotations

import dataclasses
import hashlib
import struct
from enum import Enum

import msgspec

from crimson.bonuses.pool import BonusPool
from crimson.creatures.runtime import CreaturePool
from crimson.effects import EffectPool, FxQueue, FxQueueRotated, ParticlePool, SpriteEffectPool
from crimson.persistence.save_status import GameStatus
from crimson.projectiles.runtime import ProjectilePool, SecondaryProjectilePool
from crimson.sim.sessions import DeterministicSession
from grim.rand import CrtRand, RecordingCrand

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
    if isinstance(value, msgspec.Struct):
        fields = {name: _state_value(getattr(value, name)) for name in value.__struct_fields__}
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
