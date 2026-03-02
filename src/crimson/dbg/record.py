from __future__ import annotations

import hashlib
import platform
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, cast

import msgspec

from grim.geom import Vec2

from ..bonuses import BonusId
from ..replay import load_replay_file
from ..replay.checkpoints import ReplayCheckpoint, ReplayEventSummary, ReplayPerkSnapshot, ReplayPlayerCheckpoint
from ..replay.diagnostic_trace_native import ReplayTickTraceRow, decode_replay_tick_trace_msgpack_stream
from ..replay.types import WEAPON_USAGE_COUNT, Replay
from ..sim.driver.replay_runner import run_replay
from ..sim.world_state import WorldState
from ..weapons import WeaponId
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

_REPO_ROOT = Path(__file__).resolve().parents[3]
_ZIG_ROOT = _REPO_ROOT / "crimson-zig"
_ZIG_BIN = _ZIG_ROOT / "zig-out" / "bin" / "crimson-zig"


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
    impl: Literal["python", "zig"],
    strict_events: bool,
    config_extra: dict[str, object] | None = None,
) -> TraceMeta:
    tick_start = min((row.tick_index for row in tick_rows), default=-1)
    tick_end = max((row.tick_index for row in tick_rows), default=-1)
    replay_fingerprint = _build_replay_fingerprint(replay_path=replay_path, replay=replay)
    channels_sorted = sorted(channels_seen)
    config = {
        "strict_events": bool(strict_events),
        "impl": str(impl),
    }
    if config_extra is not None:
        config.update(config_extra)
    return TraceMeta(
        trace_format_version=TRACE_FORMAT_VERSION,
        trace_schema_version=TRACE_SCHEMA_VERSION,
        created_utc=datetime.now(tz=UTC).isoformat(),
        producer={
            "impl": str(impl),
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
        config=config,
    )


def _record_replay_to_trace_python(
    *,
    replay_path: Path,
    out_path: Path,
    strict_events: bool,
    chunk_ticks: int,
) -> TraceSummary:
    replay = load_replay_file(replay_path)

    replay_tick_count = len(replay.inputs)
    checkpoint_ticks = set(range(replay_tick_count))
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
        max_ticks=None,
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
            "timing_samples": [],
        }

        if not (0 <= tick_index < len(replay_dt_rows)):
            raise ValueError(f"missing replay dt_ms_i32 row for tick {tick_index}")
        tick_dt_ms_i32 = int(replay_dt_rows[tick_index])
        if tick_dt_ms_i32 < 0:
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
        impl="python",
        strict_events=strict_events,
        config_extra=None,
    )
    return write_trace(
        out_path,
        meta=meta,
        ticks=tick_rows,
        chunk_ticks=max(1, chunk_ticks),
    )


def _command_detail(run: subprocess.CompletedProcess[str]) -> str:
    stderr = str(run.stderr).strip()
    stdout = str(run.stdout).strip()
    if stderr:
        return stderr
    if stdout:
        return stdout
    return "(no command output)"


def _run_process(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=False,
            text=True,
            capture_output=True,
        )
    except OSError as exc:
        joined = " ".join(command)
        raise ValueError(f"failed to run command: {joined}: {exc}") from exc


def _parse_quest_stage(quest_level: str) -> tuple[int, int]:
    raw = str(quest_level).strip()
    if not raw:
        return 0, 0
    major_raw, sep, minor_raw = raw.partition(".")
    if not sep:
        return 0, 0
    try:
        major = int(major_raw)
        minor = int(minor_raw)
    except ValueError:
        return 0, 0
    if major < 0 or minor < 0:
        return 0, 0
    return major, minor


def _weapon_id_from_trace(value: int | str) -> WeaponId:
    if isinstance(value, str):
        raw = str(value).strip()
        try:
            parsed = int(raw)
        except ValueError as exc:
            raise ValueError(f"invalid weapon_id in zig trace: {value!r}") from exc
    else:
        parsed = int(value)
    try:
        return WeaponId(parsed)
    except ValueError as exc:
        raise ValueError(f"unsupported weapon_id in zig trace: {parsed}") from exc


def _entity_samples_from_zig_row(
    row: ReplayTickTraceRow,
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
    for creature in row.entities.creatures:
        index = int(creature.index)
        generation = creature_state.next_generation(index=index)
        creatures.append(
            CreatureEntitySample(
                uid=index,
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
    for projectile in row.entities.projectiles:
        index = int(projectile.index)
        generation = projectile_state.next_generation(index=index)
        projectiles.append(
            ProjectileEntitySample(
                uid=index,
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
    for projectile in row.entities.secondary_projectiles:
        index = int(projectile.index)
        generation = secondary_state.next_generation(index=index)
        secondary_projectiles.append(
            SecondaryProjectileEntitySample(
                uid=index,
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
    for bonus in row.entities.bonuses:
        index = int(bonus.index)
        generation = bonus_state.next_generation(index=index)
        bonuses.append(
            BonusEntitySample(
                uid=index,
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


def _sim_state_from_zig_row(
    row: ReplayTickTraceRow,
    *,
    replay: Replay,
    quest_stage_major: int,
    quest_stage_minor: int,
) -> SimStateSnapshot:
    usage_counts = [int(value) for value in replay.header.status.weapon_usage_counts]
    expected_usage_count = int(WEAPON_USAGE_COUNT)
    if len(usage_counts) != expected_usage_count:
        raise ValueError(
            "replay header status.weapon_usage_counts length mismatch: "
            f"expected {expected_usage_count}, got {len(usage_counts)}",
        )

    player = row.player_state
    weapon = player.weapon
    weapon_id = _weapon_id_from_trace(weapon.weapon_id)
    return SimStateSnapshot(
        gameplay=SnapshotGameplay(
            mode_id=int(replay.header.game_mode_id),
            quest_stage_major=int(quest_stage_major),
            quest_stage_minor=int(quest_stage_minor),
            perk_pending_count=int(row.gameplay_state.perk_selection.pending_count),
            perk_choices_dirty=False,
            bonus_timers=SnapshotBonusTimers(
                weapon_power_up_ms=bonus_timer_ms(float(row.gameplay_state.bonuses.weapon_power_up)),
                reflex_boost_ms=bonus_timer_ms(float(row.gameplay_state.bonuses.reflex_boost)),
                energizer_ms=bonus_timer_ms(float(row.gameplay_state.bonuses.energizer)),
                double_experience_ms=bonus_timer_ms(float(row.gameplay_state.bonuses.double_experience)),
                freeze_ms=bonus_timer_ms(float(row.gameplay_state.bonuses.freeze)),
            ),
            status=SnapshotStatus(
                quest_unlock_index=0,
                quest_unlock_index_full=0,
                weapon_usage_counts=usage_counts,
            ),
        ),
        players=[
            SnapshotPlayer(
                index=int(player.index),
                pos=SnapshotVec2(x=float(player.pos.x), y=float(player.pos.y)),
                health=float(player.health),
                weapon=SnapshotWeapon(
                    weapon_id=int(weapon_id),
                    ammo=float(weapon.ammo),
                    clip_size=int(weapon.clip_size),
                    reload_active=bool(weapon.reload_active),
                    reload_timer=float(weapon.reload_timer),
                    reload_timer_max=float(weapon.reload_timer_max),
                    shot_cooldown=float(weapon.shot_cooldown),
                ),
                experience=int(player.experience),
                level=int(player.level),
            ),
        ],
    )


def _rng_marks_from_zig_row(row: ReplayTickTraceRow) -> dict[str, int]:
    marks = canonical_rng_marks(
        rng_state=int(row.rng.rng_state),
        rng_stream=[],
    )
    marks.update(
        {
            "rng_after_perk_effects": int(row.rng.rng_after_perk_effects),
            "rng_after_creatures": int(row.rng.rng_after_creatures),
            "rng_after_projectiles": int(row.rng.rng_after_projectiles),
            "rng_after_secondary_projectiles": int(row.rng.rng_after_secondary_projectiles),
            "rng_after_particles": int(row.rng.rng_after_particles),
            "rng_after_player_update": int(row.rng.rng_after_player_update),
            "rng_after_stage_spawns": int(row.rng.rng_after_stage_spawns),
            "rng_after_wave_spawns": int(row.rng.rng_after_wave_spawns),
            "rng_after_spawns": int(row.rng.rng_after_spawns),
            "rng_after_bonus_update": int(row.rng.rng_after_bonus_update),
        },
    )
    return marks


def _checkpoint_from_zig_row(row: ReplayTickTraceRow, *, rng_marks: dict[str, int]) -> ReplayCheckpoint:
    player = row.player_state
    weapon = player.weapon
    weapon_id = _weapon_id_from_trace(weapon.weapon_id)
    checkpoint_player = ReplayPlayerCheckpoint(
        pos=Vec2(
            round(float(player.pos.x), 4),
            round(float(player.pos.y), 4),
        ),
        health=round(float(player.health), 4),
        weapon_id=weapon_id,
        ammo=round(float(weapon.ammo), 4),
        experience=int(player.experience),
        level=int(player.level),
    )
    bonus_timers = {
        str(BonusId.WEAPON_POWER_UP): bonus_timer_ms(float(row.gameplay_state.bonuses.weapon_power_up)),
        str(BonusId.REFLEX_BOOST): bonus_timer_ms(float(row.gameplay_state.bonuses.reflex_boost)),
        str(BonusId.ENERGIZER): bonus_timer_ms(float(row.gameplay_state.bonuses.energizer)),
        str(BonusId.DOUBLE_EXPERIENCE): bonus_timer_ms(float(row.gameplay_state.bonuses.double_experience)),
        str(BonusId.FREEZE): bonus_timer_ms(float(row.gameplay_state.bonuses.freeze)),
    }
    perk = ReplayPerkSnapshot(
        pending_count=int(row.gameplay_state.perk_selection.pending_count),
        choices_dirty=False,
        choices=[],
        player_nonzero_counts=[[]],
    )
    return ReplayCheckpoint(
        tick_index=int(row.tick_index),
        rng_state=int(row.rng.rng_state),
        elapsed_ms=int(row.timing.elapsed_ms),
        score_xp=int(row.summary.score_xp),
        kills=int(row.summary.kills),
        creature_count=int(row.summary.creature_count),
        perk_pending=int(row.summary.perk_pending),
        players=[checkpoint_player],
        bonus_timers=bonus_timers,
        state_hash="",
        command_hash="",
        rng_marks=dict(rng_marks),
        deaths=[],
        perk=perk,
        events=ReplayEventSummary(),
    )


def _build_tick_rows_from_zig_trace(
    *,
    replay: Replay,
    zig_rows: list[ReplayTickTraceRow],
) -> tuple[list[TickRecord], set[str]]:
    expected_ticks = len(replay.inputs)
    if len(zig_rows) != expected_ticks:
        raise ValueError(
            "zig trace tick count mismatch: "
            f"expected {expected_ticks}, got {len(zig_rows)}",
        )

    rows_sorted = sorted(zig_rows, key=lambda row: int(row.tick_index))
    for expected_tick, row in enumerate(rows_sorted):
        if int(row.tick_index) != int(expected_tick):
            raise ValueError(
                "zig trace tick index mismatch: "
                f"expected tick {expected_tick}, got {int(row.tick_index)}",
            )

    replay_dt_rows = list(replay.dt_ms_i32)
    if len(replay_dt_rows) != expected_ticks:
        raise ValueError(
            "replay dt length mismatch for zig trace conversion: "
            f"expected {expected_ticks}, got {len(replay_dt_rows)}",
        )

    quest_stage_major, quest_stage_minor = _parse_quest_stage(str(replay.header.quest_level))
    creature_state = _EntityGenerationState()
    projectile_state = _EntityGenerationState()
    secondary_state = _EntityGenerationState()
    bonus_state = _EntityGenerationState()

    tick_rows: list[TickRecord] = []
    channels_seen: set[str] = set()
    for row in rows_sorted:
        tick_index = int(row.tick_index)
        if not (0 <= tick_index < len(replay_dt_rows)):
            raise ValueError(f"missing replay dt_ms_i32 row for tick {tick_index}")
        dt_ms_i32 = int(replay_dt_rows[tick_index])
        if dt_ms_i32 < 0:
            raise ValueError(f"invalid replay dt_ms_i32 at tick {tick_index}: {dt_ms_i32}")

        rng_stream: list[RngStreamRow] = []
        rng_marks = _rng_marks_from_zig_row(row)
        checkpoint = _checkpoint_from_zig_row(row, rng_marks=rng_marks)
        sim_state = _sim_state_from_zig_row(
            row,
            replay=replay,
            quest_stage_major=quest_stage_major,
            quest_stage_minor=quest_stage_minor,
        )
        entity_samples = _entity_samples_from_zig_row(
            row,
            creature_state=creature_state,
            projectile_state=projectile_state,
            secondary_state=secondary_state,
            bonus_state=bonus_state,
        )
        channels: dict[str, object] = {
            "checkpoint": checkpoint_to_channel(checkpoint),
            "sim_state": cast("dict[str, object]", msgspec.to_builtins(sim_state)),
            "entity_samples": cast("dict[str, object]", msgspec.to_builtins(entity_samples)),
            "rng_marks": dict(rng_marks),
            "rng_stream": msgspec.to_builtins(rng_stream),
            "timing_samples": [],
        }
        channels_seen.update(channels.keys())
        tick_rows.append(
            TickRecord(
                tick_index=tick_index,
                elapsed_ms=int(row.timing.elapsed_ms),
                dt_ms_i32=dt_ms_i32,
                mode_id=int(replay.header.game_mode_id),
                phase_markers=[],
                channels=channels,
            ),
        )

    return tick_rows, channels_seen


def _record_replay_to_trace_zig(
    *,
    replay_path: Path,
    out_path: Path,
    strict_events: bool,
    chunk_ticks: int,
) -> tuple[TraceSummary, list[str]]:
    if not bool(strict_events):
        raise ValueError("strict_events=False is unsupported for zig dbg record")

    replay = load_replay_file(replay_path)
    if int(replay.header.player_count) != 1:
        raise ValueError(
            "zig dbg record currently supports only single-player replays; "
            f"got player_count={int(replay.header.player_count)}",
        )

    build_run = _run_process(["zig", "build"], cwd=_ZIG_ROOT)
    if int(build_run.returncode) != 0:
        raise ValueError(
            "zig build failed: "
            f"exit={int(build_run.returncode)} detail={_command_detail(build_run)}",
        )

    warnings: list[str] = []
    with tempfile.TemporaryDirectory(prefix="crimson-zig-trace-") as temp_dir:
        trace_path = Path(temp_dir) / "zig_trace.msgpack"
        verify_cmd = [
            str(_ZIG_BIN),
            "replay",
            "verify",
            str(replay_path),
            "--debug-trace-msgpack",
            str(trace_path),
            "--format",
            "json",
        ]
        verify_run = _run_process(verify_cmd, cwd=_REPO_ROOT)
        if not trace_path.is_file():
            raise ValueError(
                "zig trace generation failed: replay verify did not produce trace output; "
                f"exit={int(verify_run.returncode)} detail={_command_detail(verify_run)}",
            )
        try:
            zig_rows = decode_replay_tick_trace_msgpack_stream(trace_path)
        except ValueError as exc:
            raise ValueError(f"zig trace decoding failed: {exc}") from exc

        if int(verify_run.returncode) != 0:
            warning = (
                f"warning: zig replay verify exited {int(verify_run.returncode)}; "
                "continuing with emitted trace"
            )
            stderr = str(verify_run.stderr).strip()
            if stderr:
                warning = f"{warning}: {stderr.splitlines()[0]}"
            warnings.append(warning)

    tick_rows, channels_seen = _build_tick_rows_from_zig_trace(
        replay=replay,
        zig_rows=zig_rows,
    )
    meta = _build_trace_meta(
        replay_path=replay_path,
        replay=replay,
        tick_rows=tick_rows,
        channels_seen=channels_seen,
        impl="zig",
        strict_events=True,
        config_extra={
            "zig_build_policy": "always",
            "zig_exit_code": int(verify_run.returncode),
            "zig_stderr_present": bool(str(verify_run.stderr).strip()),
        },
    )
    summary = write_trace(
        out_path,
        meta=meta,
        ticks=tick_rows,
        chunk_ticks=max(1, chunk_ticks),
    )
    return summary, warnings


def record_replay_to_trace(
    *,
    replay_path: Path,
    out_path: Path,
    impl: Literal["python", "zig"] = "python",
    strict_events: bool = True,
    chunk_ticks: int = 256,
    warnings_out: list[str] | None = None,
) -> TraceSummary:
    replay_path = Path(replay_path)
    out_path = Path(out_path)
    if warnings_out is None:
        warnings_out = []
    if str(impl) == "python":
        summary = _record_replay_to_trace_python(
            replay_path=replay_path,
            out_path=out_path,
            strict_events=strict_events,
            chunk_ticks=chunk_ticks,
        )
        return summary
    if str(impl) == "zig":
        summary, warnings = _record_replay_to_trace_zig(
            replay_path=replay_path,
            out_path=out_path,
            strict_events=strict_events,
            chunk_ticks=chunk_ticks,
        )
        warnings_out.extend(warnings)
        return summary
    raise ValueError(f"unsupported dbg record impl: {impl!r}")
