from __future__ import annotations

import hashlib
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import msgspec

from ..replay import load_replay_file
from ..replay.checkpoints import ReplayCheckpoint
from ..replay.types import WEAPON_USAGE_COUNT, Replay
from ..sim.driver.replay_runner import run_replay
from ..sim.world_state import WorldState
from .canonical_channels import (
    BonusEntitySample,
    CreatureEntitySample,
    EntitySamplesSnapshot,
    ProjectileEntitySample,
    RngStreamRow,
    SecondaryProjectileEntitySample,
    SimStateSnapshot,
    SnapshotBonusTimers,
    SnapshotGameplay,
    SnapshotPlayer,
    SnapshotStatus,
    SnapshotVec2,
    SnapshotWeapon,
    bonus_timer_ms,
)
from .checkpoint_codec import checkpoint_to_channel
from .rng import canonical_rng_marks
from .schema import TRACE_FORMAT_VERSION, TRACE_SCHEMA_VERSION, TickRecord, TraceMeta, channel_versions_for
from .trace import TraceSummary, write_trace


class _EntityGenerationState(msgspec.Struct):
    generation_by_index: dict[int, int] = msgspec.field(default_factory=dict)
    active_indices: set[int] = msgspec.field(default_factory=set)
    _seen_in_tick: set[int] = msgspec.field(default_factory=set)

    def begin_tick(self) -> None:
        self._seen_in_tick.clear()

    def end_tick(self) -> None:
        self.active_indices = set(self._seen_in_tick)

    def next_generation(self, *, index: int) -> int:
        idx = int(index)
        if idx not in self.generation_by_index:
            self.generation_by_index[idx] = 0
        if idx not in self.active_indices:
            self.generation_by_index[idx] += 1
        self._seen_in_tick.add(idx)
        return int(self.generation_by_index[idx])


def _fingerprint(path: Path) -> dict[str, object]:
    stat = path.stat()
    raw = path.read_bytes()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _rng_stream_from_draws(draws: list[tuple[int, int, int]]) -> list[RngStreamRow]:
    rows: list[RngStreamRow] = []
    for index, row in enumerate(draws):
        state_before_u32, value_15, state_after_u32 = row
        rows.append(
            RngStreamRow(
                tick_call_index=int(index) + 1,
                value_15=int(value_15),
                state_before_u32=int(state_before_u32),
                state_after_u32=int(state_after_u32),
                caller_static=None,
                branch_id=None,
            ),
        )
    return rows


def _entity_samples_for_world(
    world: WorldState,
    *,
    creature_state: _EntityGenerationState,
    projectile_state: _EntityGenerationState,
    secondary_state: _EntityGenerationState,
    bonus_state: _EntityGenerationState,
) -> EntitySamplesSnapshot:
    creature_state.begin_tick()
    projectile_state.begin_tick()
    secondary_state.begin_tick()
    bonus_state.begin_tick()

    creatures: list[CreatureEntitySample] = []
    for index, creature in enumerate(world.creatures.entries):
        if not creature.active:
            continue
        generation = creature_state.next_generation(index=index)
        creatures.append(
            CreatureEntitySample(
                uid=int(index),
                generation=generation,
                pool_kind="creature",
                index=index,
                active=True,
                type_id=int(creature.type_id),
                hp=float(creature.hp),
                pos=SnapshotVec2(x=float(creature.pos.x), y=float(creature.pos.y)),
                flags=int(creature.flags),
                ai_mode=int(creature.ai_mode),
                link_index=int(creature.link_index),
                heading=float(creature.heading),
                target_heading=float(creature.target_heading),
                orbit_angle=float(creature.orbit_angle),
                orbit_radius=float(creature.orbit_radius),
                lifecycle_stage=float(creature.lifecycle_stage),
            ),
        )

    projectiles: list[ProjectileEntitySample] = []
    for index, projectile in enumerate(world.state.projectiles.entries):
        if not projectile.active:
            continue
        generation = projectile_state.next_generation(index=index)
        projectiles.append(
            ProjectileEntitySample(
                uid=int(index),
                generation=generation,
                pool_kind="projectile",
                index=index,
                active=True,
                type_id=int(projectile.type_id),
                angle=float(projectile.angle),
                pos=SnapshotVec2(x=float(projectile.pos.x), y=float(projectile.pos.y)),
                vel=SnapshotVec2(x=float(projectile.vel.x), y=float(projectile.vel.y)),
                life_timer=float(projectile.life_timer),
                speed_scale=float(projectile.speed_scale),
                damage_pool=float(projectile.damage_pool),
                hit_radius=float(projectile.hit_radius),
                travel_budget=float(projectile.travel_budget),
                owner_id=int(projectile.owner_id),
            ),
        )

    secondary_projectiles: list[SecondaryProjectileEntitySample] = []
    for index, projectile in enumerate(world.state.secondary_projectiles.entries):
        if not projectile.active:
            continue
        generation = secondary_state.next_generation(index=index)
        secondary_projectiles.append(
            SecondaryProjectileEntitySample(
                uid=int(index),
                generation=generation,
                pool_kind="secondary_projectile",
                index=index,
                active=True,
                type_id=int(projectile.type_id),
                angle=float(projectile.angle),
                pos=SnapshotVec2(x=float(projectile.pos.x), y=float(projectile.pos.y)),
                vel=SnapshotVec2(x=float(projectile.vel.x), y=float(projectile.vel.y)),
                speed=float(projectile.speed),
                trail_timer=float(projectile.trail_timer),
                owner_id=int(projectile.owner_id),
                target_id=int(projectile.target_id),
            ),
        )

    bonuses: list[BonusEntitySample] = []
    for index, bonus in enumerate(world.state.bonus_pool.entries):
        if int(bonus.bonus_id) == 0:
            continue
        generation = bonus_state.next_generation(index=index)
        bonuses.append(
            BonusEntitySample(
                uid=int(index),
                generation=generation,
                pool_kind="bonus",
                index=index,
                active=True,
                bonus_id=int(bonus.bonus_id),
                picked=bool(bonus.picked),
                time_left=float(bonus.time_left),
                time_max=float(bonus.time_max),
                pos=SnapshotVec2(x=float(bonus.pos.x), y=float(bonus.pos.y)),
                amount=int(bonus.amount),
            ),
        )

    creature_state.end_tick()
    projectile_state.end_tick()
    secondary_state.end_tick()
    bonus_state.end_tick()

    return EntitySamplesSnapshot(
        creatures=creatures,
        projectiles=projectiles,
        secondary_projectiles=secondary_projectiles,
        bonuses=bonuses,
    )


def _status_snapshot_from_world(world: WorldState) -> SnapshotStatus:
    gameplay = world.state
    if gameplay.status is None:
        raise ValueError("gameplay status missing while recording trace")
    raw_counts = gameplay.status.data["weapon_usage_counts"]
    counts = [int(value) for value in list(raw_counts)]
    expected_usage_count = int(WEAPON_USAGE_COUNT)
    if len(counts) != expected_usage_count:
        raise ValueError(
            "gameplay status weapon_usage_counts length mismatch: "
            f"expected {expected_usage_count}, got {len(counts)}",
        )
    return SnapshotStatus(
        quest_unlock_index=int(gameplay.status.quest_unlock_index),
        quest_unlock_index_full=int(gameplay.status.quest_unlock_index_full),
        weapon_usage_counts=counts,
    )


def _sim_state_from_world(world: WorldState, *, replay: Replay) -> SimStateSnapshot:
    gameplay = world.state
    players: list[SnapshotPlayer] = []
    for player in world.players:
        players.append(
            SnapshotPlayer(
                index=int(player.index),
                pos=SnapshotVec2(x=float(player.pos.x), y=float(player.pos.y)),
                health=float(player.health),
                weapon=SnapshotWeapon(
                    weapon_id=int(player.weapon.weapon_id),
                    ammo=float(player.weapon.ammo),
                    clip_size=int(player.weapon.clip_size),
                    reload_active=bool(player.weapon.reload_active),
                    reload_timer=float(player.weapon.reload_timer),
                    reload_timer_max=float(player.weapon.reload_timer_max),
                    shot_cooldown=float(player.weapon.shot_cooldown),
                ),
                experience=int(player.experience),
                level=int(player.level),
            ),
        )
    return SimStateSnapshot(
        gameplay=SnapshotGameplay(
            mode_id=int(replay.header.game_mode_id),
            quest_stage_major=int(gameplay.quest_stage_major),
            quest_stage_minor=int(gameplay.quest_stage_minor),
            perk_pending_count=int(gameplay.perk_selection.pending_count),
            perk_choices_dirty=bool(gameplay.perk_selection.choices_dirty),
            bonus_timers=SnapshotBonusTimers(
                weapon_power_up_ms=bonus_timer_ms(float(gameplay.bonuses.weapon_power_up)),
                reflex_boost_ms=bonus_timer_ms(float(gameplay.bonuses.reflex_boost)),
                energizer_ms=bonus_timer_ms(float(gameplay.bonuses.energizer)),
                double_experience_ms=bonus_timer_ms(float(gameplay.bonuses.double_experience)),
                freeze_ms=bonus_timer_ms(float(gameplay.bonuses.freeze)),
            ),
            status=_status_snapshot_from_world(world),
        ),
        players=players,
    )


def _build_replay_fingerprint(*, replay_path: Path, replay: Replay) -> dict[str, object]:
    replay_fingerprint = _fingerprint(replay_path)
    replay_fingerprint["tick_rate"] = replay.header.tick_rate
    replay_fingerprint["seed"] = replay.header.seed
    replay_fingerprint["mode_id"] = replay.header.game_mode_id
    replay_fingerprint["quest_level"] = str(replay.header.quest_level)
    return replay_fingerprint


def _build_trace_meta(
    *,
    replay_path: Path,
    replay: Replay,
    tick_rows: list[TickRecord],
    channels_seen: set[str],
    strict_events: bool,
    max_ticks: int | None,
) -> TraceMeta:
    tick_start = min((row.tick_index for row in tick_rows), default=-1)
    tick_end = max((row.tick_index for row in tick_rows), default=-1)
    replay_fingerprint = _build_replay_fingerprint(replay_path=replay_path, replay=replay)
    channels_sorted = sorted(channels_seen)
    return TraceMeta(
        trace_format_version=TRACE_FORMAT_VERSION,
        trace_schema_version=TRACE_SCHEMA_VERSION,
        created_utc=datetime.now(tz=UTC).isoformat(),
        producer={
            "impl": "python",
            "impl_version": "",
            "platform": str(platform.system()),
            "arch": str(platform.machine()),
        },
        source=replay_fingerprint,
        channels=channels_sorted,
        channel_versions=channel_versions_for(channels_sorted),
        tick_range={
            "start_tick": tick_start,
            "end_tick": tick_end,
            "tick_count": len(tick_rows),
        },
        config={
            "strict_events": bool(strict_events),
            "max_ticks": max_ticks,
        },
    )


def _record_replay_to_trace_python(
    *,
    replay_path: Path,
    out_path: Path,
    max_ticks: int | None,
    strict_events: bool,
    chunk_ticks: int,
) -> TraceSummary:
    replay = load_replay_file(replay_path)

    replay_tick_count = len(replay.inputs)
    tick_count = replay_tick_count if max_ticks is None else min(replay_tick_count, int(max_ticks))
    checkpoint_ticks = set(range(tick_count))
    checkpoints: list[ReplayCheckpoint] = []

    entity_samples_by_tick: dict[int, EntitySamplesSnapshot] = {}
    sim_state_by_tick: dict[int, SimStateSnapshot] = {}
    rng_stream_by_tick: dict[int, list[RngStreamRow]] = {}
    creature_state = _EntityGenerationState()
    projectile_state = _EntityGenerationState()
    secondary_state = _EntityGenerationState()
    bonus_state = _EntityGenerationState()

    def _tick_observer(tick_index: int, world: WorldState) -> None:
        entity_samples_by_tick[tick_index] = _entity_samples_for_world(
            world,
            creature_state=creature_state,
            projectile_state=projectile_state,
            secondary_state=secondary_state,
            bonus_state=bonus_state,
        )
        sim_state_by_tick[tick_index] = _sim_state_from_world(world, replay=replay)

    def _tick_rng_trace_observer(tick_index: int, draws: list[tuple[int, int, int]]) -> None:
        rng_stream_by_tick[int(tick_index)] = _rng_stream_from_draws(draws)

    run_replay(
        replay,
        max_ticks=max_ticks,
        strict_events=bool(strict_events),
        trace_rng=True,
        checkpoints_out=checkpoints,
        checkpoint_ticks=checkpoint_ticks,
        tick_observer=_tick_observer,
        tick_rng_trace_observer=_tick_rng_trace_observer,
    )

    tick_rows: list[TickRecord] = []
    channels_seen: set[str] = set()
    replay_dt_rows = list(replay.dt_ms_i32)
    for checkpoint in sorted(checkpoints, key=lambda row: row.tick_index):
        tick_index = int(checkpoint.tick_index)
        if tick_index not in rng_stream_by_tick:
            raise ValueError(f"missing runtime rng stream for tick {tick_index}")
        if tick_index not in entity_samples_by_tick:
            raise ValueError(f"missing entity_samples snapshot for tick {tick_index}")
        if tick_index not in sim_state_by_tick:
            raise ValueError(f"missing sim_state snapshot for tick {tick_index}")

        entity_samples_obj = entity_samples_by_tick[tick_index]
        sim_state_obj = sim_state_by_tick[tick_index]
        rng_stream = list(rng_stream_by_tick[tick_index])
        trace_rng_marks = canonical_rng_marks(
            rng_state=int(checkpoint.rng_state),
            rng_stream=rng_stream,
        )
        trace_checkpoint = msgspec.structs.replace(
            checkpoint,
            state_hash="",
            command_hash="",
            rng_marks=dict(trace_rng_marks),
        )

        channels: dict[str, object] = {
            "checkpoint": checkpoint_to_channel(trace_checkpoint),
            "sim_state": cast("dict[str, object]", msgspec.to_builtins(sim_state_obj)),
            "entity_samples": cast("dict[str, object]", msgspec.to_builtins(entity_samples_obj)),
            "rng_marks": dict(trace_rng_marks),
            "rng_stream": msgspec.to_builtins(rng_stream),
        }

        if not (0 <= tick_index < len(replay_dt_rows)):
            raise ValueError(f"missing replay dt_ms_i32 row for tick {tick_index}")
        tick_dt_ms_i32 = int(replay_dt_rows[tick_index])
        if tick_dt_ms_i32 <= 0:
            raise ValueError(f"invalid replay dt_ms_i32 at tick {tick_index}: {tick_dt_ms_i32}")

        channels_seen.update(channels.keys())
        tick_rows.append(
            TickRecord(
                tick_index=tick_index,
                elapsed_ms=int(checkpoint.elapsed_ms),
                dt_ms_i32=tick_dt_ms_i32,
                mode_id=int(replay.header.game_mode_id),
                phase_markers=[],
                channels=channels,
            ),
        )

    meta = _build_trace_meta(
        replay_path=replay_path,
        replay=replay,
        tick_rows=tick_rows,
        channels_seen=channels_seen,
        strict_events=strict_events,
        max_ticks=max_ticks,
    )
    return write_trace(
        out_path,
        meta=meta,
        ticks=tick_rows,
        chunk_ticks=max(1, chunk_ticks),
    )


def record_replay_to_trace(
    *,
    replay_path: Path,
    out_path: Path,
    max_ticks: int | None = None,
    strict_events: bool = True,
    chunk_ticks: int = 256,
) -> TraceSummary:
    replay_path = Path(replay_path)
    out_path = Path(out_path)
    return _record_replay_to_trace_python(
        replay_path=replay_path,
        out_path=out_path,
        max_ticks=max_ticks,
        strict_events=strict_events,
        chunk_ticks=chunk_ticks,
    )
