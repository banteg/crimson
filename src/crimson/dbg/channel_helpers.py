from __future__ import annotations

from ..replay.checkpoints import ReplayCheckpoint
from .canonical_channels import (
    BonusEntitySample,
    CreatureEntitySample,
    EntitySamplesSnapshot,
    ProjectileEntitySample,
    RngStreamRow,
    SecondaryProjectileEntitySample,
    SimStateSnapshot,
    TimingSampleRow,
)
from .schema import TickRecord
from .trace import TraceError

ENTITY_SAMPLE_KINDS = ("creatures", "projectiles", "secondary_projectiles", "bonuses")

EntitySampleRow = CreatureEntitySample | ProjectileEntitySample | SecondaryProjectileEntitySample | BonusEntitySample


def _require_row(row: TickRecord | None, *, channel_name: str) -> TickRecord:
    if row is None:
        raise TraceError(f"missing tick row for {channel_name} channel")
    return row


def checkpoint_channel(row: TickRecord | None) -> ReplayCheckpoint | None:
    return None if row is None else row.channels.checkpoint


def checkpoint_channel_required(row: TickRecord | None) -> ReplayCheckpoint:
    return _require_row(row, channel_name="checkpoint").channels.checkpoint


def sim_state_channel(row: TickRecord | None) -> SimStateSnapshot | None:
    return None if row is None else row.channels.sim_state


def sim_state_channel_required(row: TickRecord | None) -> SimStateSnapshot:
    return _require_row(row, channel_name="sim_state").channels.sim_state


def entity_samples_channel(row: TickRecord | None) -> EntitySamplesSnapshot | None:
    return None if row is None else row.channels.entity_samples


def entity_samples_channel_required(row: TickRecord | None) -> EntitySamplesSnapshot:
    return _require_row(row, channel_name="entity_samples").channels.entity_samples


def rng_stream_channel_required(row: TickRecord | None) -> list[RngStreamRow]:
    return list(_require_row(row, channel_name="rng_stream").channels.rng_stream)

def timing_samples_channel_required(row: TickRecord | None) -> list[TimingSampleRow]:
    return list(_require_row(row, channel_name="timing_samples").channels.timing_samples)


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
