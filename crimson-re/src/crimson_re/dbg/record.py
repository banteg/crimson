from __future__ import annotations

import hashlib
import platform
from datetime import UTC, datetime
from pathlib import Path

import msgspec

from crimson.game_modes import GameMode
from crimson.math_parity import f32
from crimson.owner_id import OWNER_LOCAL_PLAYER
from crimson.persistence.save_status import GameStatusData
from crimson.replay import REPLAY_TICK_DT, REPLAY_TICK_RATE, PackedTickInputs, Replay, load_replay_file
from crimson.replay.checkpoints import ReplayCheckpoint
from crimson.replay.driver.playback_driver import (
    PlaybackDriver,
    PlaybackWalkObserver,
    RngTraceDraw,
    build_verify_playback_driver,
)
from crimson.replay.payloads import BuiltinObject
from crimson.replay.types import current_replay_game_version
from crimson.sim.hooks import TickResult
from crimson.sim.run_spec import RunSpec
from crimson.sim.timing import ftol_ms_i32, reflex_boost_time_scale_factor
from crimson.sim.world_state import WorldState
from grim.rand import RecordedCallerStatic

from .canonical_channels import (
    BonusEntitySample,
    CreatureEntitySample,
    EntitySamplesSnapshot,
    ProjectileEntitySample,
    ReplayInputSample,
    ReplayStepSnapshot,
    RngStreamRow,
    SecondaryProjectileEntitySample,
    SimStateSnapshot,
    SnapshotBonusTimers,
    SnapshotGameplay,
    SnapshotPlayer,
    SnapshotRgba,
    SnapshotVec2,
    SnapshotWeapon,
    TimingSampleRow,
    bonus_timer_ms,
    entity_uid,
)
from .schema import (
    TRACE_FORMAT_VERSION,
    TRACE_SCHEMA_VERSION,
    ReplayTickChannels,
    TickRecord,
    TraceMeta,
    TraceProducer,
    TraceSource,
    TraceTickRange,
)
from .trace import TraceSummary, write_trace

_TRACE_CHUNK_TICKS = 256


def _trace_f32(value: float) -> float:
    """Return the canonical f32 value stored by every CDT producer."""

    return float(f32(float(value)))


def _checkpoint_for_trace(checkpoint: ReplayCheckpoint) -> ReplayCheckpoint:
    """Keep only checkpoint fields with an exact representation in every producer."""

    events = msgspec.structs.replace(checkpoint.events, sfx_count=0, sfx_head=[], hit_head=[])
    return msgspec.structs.replace(checkpoint, deaths=[], events=events)


class _TraceRecording(msgspec.Struct, frozen=True):
    """What a recorded trace reports about its source beyond the simulated state."""

    run: RunSpec
    tick_rate: int
    status: GameStatusData
    steps: list[ReplayStepSnapshot]


def _input_samples(inputs: PackedTickInputs) -> list[ReplayInputSample]:
    return [
        ReplayInputSample(
            move_x=_trace_f32(move_x),
            move_y=_trace_f32(move_y),
            aim_x=_trace_f32(aim_x),
            aim_y=_trace_f32(aim_y),
            flags=int(flags),
        )
        for move_x, move_y, aim_x, aim_y, flags in inputs
    ]


def _replay_recording(replay: Replay) -> _TraceRecording:
    """Port replays step a fixed dt and carry only the status fields the run consumes."""

    return _TraceRecording(
        run=replay.run,
        tick_rate=REPLAY_TICK_RATE,
        status=replay.run.status.as_status_data(),
        steps=[
            ReplayStepSnapshot(
                dt=_trace_f32(REPLAY_TICK_DT),
                inputs=_input_samples(tick.inputs),
                prelude=[],
                postlude=[],
                commands=list(tick.commands),
            )
            for tick in replay.ticks
        ],
    )


def _load_recording(path: Path) -> tuple[_TraceRecording, PlaybackDriver]:
    replay = load_replay_file(path)
    return _replay_recording(replay), build_verify_playback_driver(replay, trace_rng=True, strict_rng_trace=True)


def _fingerprint(path: Path) -> BuiltinObject:
    stat = path.stat()
    raw = path.read_bytes()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def _builtin_text(payload: BuiltinObject, key: str, default: str = "") -> str:
    value = payload.get(key)
    if value is None:
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return str(value)
    return default


def _builtin_int(payload: BuiltinObject, key: str, default: int = 0) -> int:
    value = payload.get(key)
    if isinstance(value, (bool, int, float, str)):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _rng_stream_from_draws(draws: list[tuple[int, int, int, RecordedCallerStatic]]) -> list[RngStreamRow]:
    rows: list[RngStreamRow] = []
    for index, row in enumerate(draws):
        state_before_u32, value_15, state_after_u32, caller = row
        rows.append(
            RngStreamRow(
                tick_call_index=int(index) + 1,
                value_15=int(value_15),
                state_before_u32=int(state_before_u32),
                state_after_u32=int(state_after_u32),
                caller=caller,
            ),
        )
    return rows


def _entity_samples_for_world(
    world: WorldState,
) -> EntitySamplesSnapshot:
    creatures: list[CreatureEntitySample] = []
    for index, creature in enumerate(world.creatures.entries):
        if not creature.active:
            continue
        generation = int(creature.generation)
        target_offset = creature.target_offset
        creatures.append(
            CreatureEntitySample(
                uid=entity_uid(pool_kind="creature", index=index, generation=generation),
                generation=generation,
                pool_kind="creature",
                index=index,
                active=True,
                type_id=int(creature.type_id),
                hp=_trace_f32(creature.hp),
                pos=SnapshotVec2(x=_trace_f32(creature.pos.x), y=_trace_f32(creature.pos.y)),
                tint=SnapshotRgba(
                    r=_trace_f32(creature.tint.r),
                    g=_trace_f32(creature.tint.g),
                    b=_trace_f32(creature.tint.b),
                    a=_trace_f32(creature.tint.a),
                ),
                flags=int(creature.flags),
                ai_mode=int(creature.ai_mode),
                link_index=int(creature.link_index),
                force_target=int(creature.force_target),
                target=SnapshotVec2(x=_trace_f32(creature.target.x), y=_trace_f32(creature.target.y)),
                target_player=int(creature.target_player),
                target_offset=SnapshotVec2(
                    x=0.0 if target_offset is None else _trace_f32(target_offset.x),
                    y=0.0 if target_offset is None else _trace_f32(target_offset.y),
                ),
                heading=_trace_f32(creature.heading),
                target_heading=_trace_f32(creature.target_heading),
                dot_tick_timer=_trace_f32(creature.dot_tick_timer),
                attack_cooldown=_trace_f32(creature.attack_cooldown),
                orbit_angle=_trace_f32(creature.orbit_angle),
                orbit_radius=_trace_f32(creature.orbit_radius),
                death_timer=_trace_f32(creature.death_timer),
                vel=SnapshotVec2(x=_trace_f32(creature.vel.x), y=_trace_f32(creature.vel.y)),
                move_speed=_trace_f32(creature.move_speed),
            ),
        )

    projectiles: list[ProjectileEntitySample] = []
    for index, projectile in enumerate(world.state.projectiles.entries):
        if not projectile.active:
            continue
        generation = int(projectile.generation)
        projectiles.append(
            ProjectileEntitySample(
                uid=entity_uid(pool_kind="projectile", index=index, generation=generation),
                generation=generation,
                pool_kind="projectile",
                index=index,
                active=True,
                type_id=int(projectile.type_id),
                angle=_trace_f32(projectile.angle),
                pos=SnapshotVec2(x=_trace_f32(projectile.pos.x), y=_trace_f32(projectile.pos.y)),
                vel=SnapshotVec2(x=_trace_f32(projectile.vel.x), y=_trace_f32(projectile.vel.y)),
                life_timer=_trace_f32(projectile.life_timer),
                speed_scale=_trace_f32(projectile.speed_scale),
                damage_pool=_trace_f32(projectile.damage_pool),
                hit_radius=_trace_f32(projectile.hit_radius),
                projectile_speed=_trace_f32(projectile.projectile_speed),
                owner_id=int(projectile.owner_id),
            ),
        )

    secondary_projectiles: list[SecondaryProjectileEntitySample] = []
    for index, projectile in enumerate(world.state.secondary_projectiles.entries):
        if not projectile.active:
            continue
        generation = int(projectile.generation)
        secondary_projectiles.append(
            SecondaryProjectileEntitySample(
                uid=entity_uid(pool_kind="secondary_projectile", index=index, generation=generation),
                generation=generation,
                pool_kind="secondary_projectile",
                index=index,
                active=True,
                type_id=int(projectile.type_id),
                angle=_trace_f32(projectile.angle),
                pos=SnapshotVec2(x=_trace_f32(projectile.pos.x), y=_trace_f32(projectile.pos.y)),
                vel=SnapshotVec2(x=_trace_f32(projectile.vel.x), y=_trace_f32(projectile.vel.y)),
                speed=_trace_f32(projectile.life_timer),
                trail_distance=_trace_f32(projectile.trail_distance),
                # Native secondaries carry no owner; the capture reports -100 for them too.
                owner_id=OWNER_LOCAL_PLAYER,
                target_id=int(projectile.target_id),
            ),
        )

    bonuses: list[BonusEntitySample] = []
    for index, bonus in enumerate(world.state.bonus_pool.entries):
        if int(bonus.bonus_id) == 0:
            continue
        generation = int(bonus.generation)
        bonuses.append(
            BonusEntitySample(
                uid=entity_uid(pool_kind="bonus", index=index, generation=generation),
                generation=generation,
                pool_kind="bonus",
                index=index,
                active=True,
                bonus_id=int(bonus.bonus_id),
                picked=bool(bonus.picked),
                time_left=_trace_f32(bonus.time_left),
                time_max=_trace_f32(bonus.time_max),
                pos=SnapshotVec2(x=_trace_f32(bonus.pos.x), y=_trace_f32(bonus.pos.y)),
                amount=int(bonus.amount),
            ),
        )

    return EntitySamplesSnapshot(
        creatures=creatures,
        projectiles=projectiles,
        secondary_projectiles=secondary_projectiles,
        bonuses=bonuses,
    )


def _sim_state_from_world(world: WorldState, *, mode_id: int) -> SimStateSnapshot:
    gameplay = world.state
    players: list[SnapshotPlayer] = []
    for player in world.players:
        players.append(
            SnapshotPlayer(
                index=int(player.index),
                pos=SnapshotVec2(x=_trace_f32(player.pos.x), y=_trace_f32(player.pos.y)),
                heading=_trace_f32(player.heading),
                move_speed=_trace_f32(player.move_speed),
                move_phase=_trace_f32(player.move_phase),
                aim=SnapshotVec2(x=_trace_f32(player.aim.x), y=_trace_f32(player.aim.y)),
                aim_heading=_trace_f32(player.aim_heading),
                health=_trace_f32(player.health),
                weapon=SnapshotWeapon(
                    weapon_id=int(player.weapon.weapon_id),
                    ammo=_trace_f32(player.weapon.ammo),
                    clip_size=int(player.weapon.clip_size),
                    reload_active=bool(player.weapon.reload_active),
                    reload_timer=_trace_f32(player.weapon.reload_timer),
                    reload_timer_max=_trace_f32(player.weapon.reload_timer_max),
                    shot_cooldown=_trace_f32(player.weapon.shot_cooldown),
                ),
                experience=int(player.experience),
                level=int(player.level),
            ),
        )
    return SimStateSnapshot(
        gameplay=SnapshotGameplay(
            mode_id=int(mode_id),
            quest_stage_major=(0 if gameplay.quest_level is None else int(gameplay.quest_level.major)),
            quest_stage_minor=(0 if gameplay.quest_level is None else int(gameplay.quest_level.minor)),
            perk_pending_count=int(gameplay.perk_selection.pending_count),
            perk_choices_dirty=bool(gameplay.perk_selection.choices_dirty),
            bonus_timers=SnapshotBonusTimers(
                weapon_power_up_ms=bonus_timer_ms(float(gameplay.bonuses.weapon_power_up)),
                reflex_boost_ms=bonus_timer_ms(float(gameplay.bonuses.reflex_boost)),
                energizer_ms=bonus_timer_ms(float(gameplay.bonuses.energizer)),
                double_experience_ms=bonus_timer_ms(float(gameplay.bonuses.double_experience)),
                freeze_ms=bonus_timer_ms(float(gameplay.bonuses.freeze)),
            ),
        ),
        players=players,
    )


def _build_replay_fingerprint(*, replay_path: Path, recording: _TraceRecording) -> BuiltinObject:
    run = recording.run
    replay_fingerprint = _fingerprint(replay_path)
    replay_fingerprint["tick_rate"] = recording.tick_rate
    replay_fingerprint["seed"] = run.seed
    replay_fingerprint["mode_id"] = run.game_mode_id
    replay_fingerprint["player_count"] = run.player_count
    replay_fingerprint["quest_level"] = None if run.quest_level is None else run.quest_level.text
    return replay_fingerprint


def _source_from_replay_fingerprint(fingerprint: BuiltinObject) -> TraceSource:
    quest_level_value = fingerprint.get("quest_level")
    quest_level = str(quest_level_value) if isinstance(quest_level_value, str) and quest_level_value else None
    quest_stage_major: int | None = None
    quest_stage_minor: int | None = None
    if quest_level is not None:
        major_text, minor_text = quest_level.split(".", 1)
        quest_stage_major = int(major_text)
        quest_stage_minor = int(minor_text)
    return TraceSource(
        path=_builtin_text(fingerprint, "path"),
        sha256=_builtin_text(fingerprint, "sha256"),
        size=_builtin_int(fingerprint, "size"),
        mtime_ns=_builtin_int(fingerprint, "mtime_ns"),
        kind="replay",
        replay_sha256=_builtin_text(fingerprint, "sha256"),
        tick_rate=_builtin_int(fingerprint, "tick_rate"),
        seed=_builtin_int(fingerprint, "seed"),
        mode_id=_builtin_int(fingerprint, "mode_id"),
        player_count=_builtin_int(fingerprint, "player_count"),
        quest_level=quest_level,
        quest_stage_major=quest_stage_major,
        quest_stage_minor=quest_stage_minor,
    )


def _timing_samples_for_tick(
    *,
    tick_index: int,
    dt: float,
    dt_ms_i32: int,
    world: WorldState,
) -> list[TimingSampleRow]:
    active = bool(world.state.time_scale_active)
    reflex_boost_timer = float(world.state.bonuses.reflex_boost)
    return [
        TimingSampleRow(
            tick_index=int(tick_index),
            gameplay_frame=int(tick_index),
            phase="gpur_enter",
            write_kind="snapshot",
            frame_dt_f32=_trace_f32(dt),
            frame_dt_ms_i32=int(dt_ms_i32),
            frame_dt_ms_f32=_trace_f32(dt_ms_i32),
            time_scale_active_entry=active,
            time_scale_active_current=active,
            time_scale_factor=_trace_f32(
                reflex_boost_time_scale_factor(
                    reflex_boost_timer=reflex_boost_timer,
                    time_scale_active=active,
                ),
            ),
            bonus_reflex_boost_timer=_trace_f32(reflex_boost_timer),
            mode_fn="gameplay_update_and_render",
            player_index=None,
        ),
    ]


def _build_trace_meta(
    *,
    replay_path: Path,
    recording: _TraceRecording,
    tick_rows: list[TickRecord],
) -> TraceMeta:
    tick_start = min((row.tick_index for row in tick_rows), default=-1)
    tick_end = max((row.tick_index for row in tick_rows), default=-1)
    replay_fingerprint = _build_replay_fingerprint(replay_path=replay_path, recording=recording)
    return TraceMeta(
        trace_format_version=TRACE_FORMAT_VERSION,
        trace_schema_version=TRACE_SCHEMA_VERSION,
        created_utc=datetime.now(tz=UTC).isoformat(),
        producer=TraceProducer(
            impl="python",
            impl_version=current_replay_game_version(),
            platform=str(platform.system()),
            arch=str(platform.machine()),
        ),
        source=_source_from_replay_fingerprint(replay_fingerprint),
        tick_range=TraceTickRange(
            start_tick=tick_start,
            end_tick=tick_end,
            tick_count=len(tick_rows),
        ),
        status=recording.status,
    )


def _canonical_elapsed_ms_by_tick(steps: list[ReplayStepSnapshot]) -> list[int]:
    elapsed_ms = 0
    out: list[int] = []
    for step in steps:
        elapsed_ms += int(ftol_ms_i32(step.dt))
        out.append(elapsed_ms)
    return out


def record_replay_to_trace(
    *,
    replay_path: Path,
    out_path: Path,
) -> TraceSummary:
    """Record a CDT trace from a port replay."""
    recording, driver = _load_recording(replay_path)
    mode_id = int(recording.run.game_mode_id)
    canonical_elapsed_ms = _canonical_elapsed_ms_by_tick(recording.steps)

    checkpoint_ticks = set(range(len(recording.steps)))
    checkpoints: list[ReplayCheckpoint] = []

    entity_samples_by_tick: dict[int, EntitySamplesSnapshot] = {}
    sim_state_by_tick: dict[int, SimStateSnapshot] = {}
    rng_stream_by_tick: dict[int, list[RngStreamRow]] = {}
    timing_samples_by_tick: dict[int, list[TimingSampleRow]] = {}

    class _ReplayRecordObserver(PlaybackWalkObserver):
        def before_tick(self, tick_index: int, world: WorldState, dt_tick: float) -> None:
            dt_ms_i32 = int(ftol_ms_i32(dt_tick))
            if dt_ms_i32 < 0:
                raise ValueError(f"invalid replay dt_ms_i32 at tick {tick_index}: {dt_ms_i32}")
            timing_samples_by_tick[int(tick_index)] = _timing_samples_for_tick(
                tick_index=int(tick_index),
                dt=float(dt_tick),
                dt_ms_i32=dt_ms_i32,
                world=world,
            )

        def after_tick(self, tick_result: TickResult, world: WorldState) -> None:
            tick_index = int(tick_result.tick_index)
            if tick_index in checkpoint_ticks:
                checkpoint = driver.build_checkpoint(tick_result=tick_result)
                checkpoints.append(
                    msgspec.structs.replace(
                        checkpoint,
                        elapsed_ms=(
                            int(checkpoint.elapsed_ms)
                            if mode_id == GameMode.QUESTS
                            else int(canonical_elapsed_ms[tick_index])
                        ),
                    ),
                )
            entity_samples_by_tick[tick_index] = _entity_samples_for_world(
                world,
            )
            sim_state_by_tick[tick_index] = _sim_state_from_world(world, mode_id=mode_id)

        def rng_trace(self, tick_result: TickResult, draws: tuple[RngTraceDraw, ...]) -> None:
            rng_stream_by_tick[int(tick_result.tick_index)] = _rng_stream_from_draws(list(draws))

    driver.run(
        observer=_ReplayRecordObserver(),
    )

    tick_rows: list[TickRecord] = []
    replay_dt_rows = [ftol_ms_i32(step.dt) for step in recording.steps]
    for checkpoint in sorted(checkpoints, key=lambda row: row.tick_index):
        tick_index = int(checkpoint.tick_index)
        if tick_index not in rng_stream_by_tick:
            raise ValueError(f"missing runtime rng stream for tick {tick_index}")
        if tick_index not in entity_samples_by_tick:
            raise ValueError(f"missing entity_samples snapshot for tick {tick_index}")
        if tick_index not in sim_state_by_tick:
            raise ValueError(f"missing sim_state snapshot for tick {tick_index}")
        if tick_index not in timing_samples_by_tick:
            raise ValueError(f"missing timing_samples snapshot for tick {tick_index}")

        entity_samples_obj = entity_samples_by_tick[tick_index]
        sim_state_obj = sim_state_by_tick[tick_index]
        rng_stream = list(rng_stream_by_tick[tick_index])

        channels = ReplayTickChannels(
            replay_step=recording.steps[tick_index],
            checkpoint=_checkpoint_for_trace(checkpoint),
            sim_state=sim_state_obj,
            entity_samples=entity_samples_obj,
            rng_stream=rng_stream,
            timing_samples=list(timing_samples_by_tick[tick_index]),
        )

        if not (0 <= tick_index < len(replay_dt_rows)):
            raise ValueError(f"missing replay dt_ms_i32 row for tick {tick_index}")
        tick_dt_ms_i32 = int(replay_dt_rows[tick_index])
        if tick_dt_ms_i32 < 0:
            raise ValueError(f"invalid replay dt_ms_i32 at tick {tick_index}: {tick_dt_ms_i32}")

        tick_rows.append(
            TickRecord(
                tick_index=tick_index,
                elapsed_ms=int(checkpoint.elapsed_ms),
                dt_ms_i32=tick_dt_ms_i32,
                mode_id=mode_id,
                channels=channels,
            ),
        )

    meta = _build_trace_meta(
        replay_path=replay_path,
        recording=recording,
        tick_rows=tick_rows,
    )
    return write_trace(
        out_path,
        meta=meta,
        ticks=tick_rows,
        chunk_ticks=_TRACE_CHUNK_TICKS,
    )
