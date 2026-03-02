from __future__ import annotations

from typing import cast

import msgspec

from ..replay.checkpoints import ReplayCheckpoint
from .canonical_channels import (
    BonusEntitySample,
    CreatureEntitySample,
    EntitySamplesSnapshot,
    ProjectileEntitySample,
    RngStreamRow,
    SecondaryProjectileEntitySample,
    SimStateSnapshot,
)
from .schema import TickRecord
from .trace import TraceError

ENTITY_SAMPLE_KINDS = ("creatures", "projectiles", "secondary_projectiles", "bonuses")

EntitySampleRow = CreatureEntitySample | ProjectileEntitySample | SecondaryProjectileEntitySample | BonusEntitySample

def _decode_channel(value: object, *, channel_name: str, target: object) -> object:
    try:
        return msgspec.convert(value, type=target)
    except (msgspec.ValidationError, TypeError, ValueError) as exc:
        raise TraceError(f"invalid {channel_name} channel payload") from exc


def _require_row(row: TickRecord | None, *, channel_name: str) -> TickRecord:
    if row is None:
        raise TraceError(f"missing tick row for {channel_name} channel")
    return row


def _require_channel_payload(row: TickRecord | None, *, channel_name: str) -> object:
    record = _require_row(row, channel_name=channel_name)
    if channel_name not in record.channels:
        raise TraceError(f"missing {channel_name} channel payload")
    return record.channels[channel_name]


def checkpoint_channel(row: TickRecord | None) -> ReplayCheckpoint | None:
    if row is None:
        return None
    payload = row.channels.get("checkpoint")
    if payload is None:
        return None
    return cast("ReplayCheckpoint", _decode_channel(payload, channel_name="checkpoint", target=ReplayCheckpoint))


def checkpoint_channel_required(row: TickRecord | None) -> ReplayCheckpoint:
    payload = _require_channel_payload(row, channel_name="checkpoint")
    return cast("ReplayCheckpoint", _decode_channel(payload, channel_name="checkpoint", target=ReplayCheckpoint))


def sim_state_channel(row: TickRecord | None) -> SimStateSnapshot | None:
    if row is None:
        return None
    payload = row.channels.get("sim_state")
    if payload is None:
        return None
    return cast("SimStateSnapshot", _decode_channel(payload, channel_name="sim_state", target=SimStateSnapshot))


def sim_state_channel_required(row: TickRecord | None) -> SimStateSnapshot:
    payload = _require_channel_payload(row, channel_name="sim_state")
    return cast("SimStateSnapshot", _decode_channel(payload, channel_name="sim_state", target=SimStateSnapshot))


def entity_samples_channel(row: TickRecord | None) -> EntitySamplesSnapshot | None:
    if row is None:
        return None
    payload = row.channels.get("entity_samples")
    if payload is None:
        return None
    return cast(
        "EntitySamplesSnapshot",
        _decode_channel(payload, channel_name="entity_samples", target=EntitySamplesSnapshot),
    )


def entity_samples_channel_required(row: TickRecord | None) -> EntitySamplesSnapshot:
    payload = _require_channel_payload(row, channel_name="entity_samples")
    return cast(
        "EntitySamplesSnapshot",
        _decode_channel(payload, channel_name="entity_samples", target=EntitySamplesSnapshot),
    )


def rng_stream_channel_required(row: TickRecord | None) -> list[RngStreamRow]:
    payload = _require_channel_payload(row, channel_name="rng_stream")
    return cast("list[RngStreamRow]", _decode_channel(payload, channel_name="rng_stream", target=list[RngStreamRow]))


def rng_marks_channel_required(row: TickRecord | None) -> dict[str, int]:
    payload = _require_channel_payload(row, channel_name="rng_marks")
    return cast("dict[str, int]", _decode_channel(payload, channel_name="rng_marks", target=dict[str, int]))


def entity_rows(samples: EntitySamplesSnapshot, *, kind: str) -> list[EntitySampleRow]:
    match str(kind):
        case "creatures":
            return [*samples.creatures]
        case "projectiles":
            return [*samples.projectiles]
        case "secondary_projectiles":
            return [*samples.secondary_projectiles]
        case "bonuses":
            return [*samples.bonuses]
        case _:
            raise ValueError(f"unsupported entity sample kind: {kind!r}")
