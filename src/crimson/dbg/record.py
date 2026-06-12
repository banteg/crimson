from __future__ import annotations

import hashlib
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import msgspec

from grim.rand import RecordedCallerStatic

from ..math_parity import f32
from ..replay import load_replay_file
from ..replay.checkpoints import ReplayCheckpoint
from ..replay.driver.playback_driver import PlaybackWalkObserver, RngTraceDraw, build_verify_playback_driver
from ..replay.types import Replay
from ..sim.hooks import TickResult
from ..sim.step_pipeline import time_scale_reflex_boost_factor
from ..sim.timing import ftol_ms_i32
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
    SnapshotVec2,
    SnapshotWeapon,
    TimingSampleRow,
    bonus_timer_ms,
)
from .payloads import BuiltinObject
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
from .trace import TraceError, TraceReader, TraceSummary, write_trace

_REPO_ROOT = Path(__file__).resolve().parents[3]
_ZIG_ROOT = _REPO_ROOT / "crimson-zig"
_ZIG_BIN = _ZIG_ROOT / "zig-out" / "bin" / "crimson-zig"
_TRACE_CHUNK_TICKS = 256


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
                owner_id=int(projectile.owner.to_legacy()),
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
                owner_id=int(projectile.owner.to_legacy()),
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


def _build_replay_fingerprint(*, replay_path: Path, replay: Replay) -> BuiltinObject:
    replay_fingerprint = _fingerprint(replay_path)
    replay_fingerprint["tick_rate"] = replay.header.tick_rate
    replay_fingerprint["seed"] = replay.header.seed
    replay_fingerprint["mode_id"] = replay.header.game_mode_id
    replay_fingerprint["quest_level"] = "" if replay.header.quest_level is None else replay.header.quest_level.text
    return replay_fingerprint


def _source_from_replay_fingerprint(fingerprint: BuiltinObject) -> TraceSource:
    return TraceSource(
        path=_builtin_text(fingerprint, "path"),
        sha256=_builtin_text(fingerprint, "sha256"),
        size=_builtin_int(fingerprint, "size"),
        mtime_ns=_builtin_int(fingerprint, "mtime_ns"),
        tick_rate=_builtin_int(fingerprint, "tick_rate"),
        seed=_builtin_int(fingerprint, "seed"),
        mode_id=_builtin_int(fingerprint, "mode_id"),
        quest_level=_builtin_text(fingerprint, "quest_level"),
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
            frame_dt_f32=float(f32(float(dt))),
            frame_dt_ms_i32=int(dt_ms_i32),
            frame_dt_ms_f32=float(dt_ms_i32),
            time_scale_active_entry=active,
            time_scale_active_current=active,
            time_scale_factor=float(
                time_scale_reflex_boost_factor(
                    reflex_boost_timer=reflex_boost_timer,
                    time_scale_active=active,
                ),
            ),
            bonus_reflex_boost_timer=reflex_boost_timer,
            mode_fn="gameplay_update_and_render",
            player_index=None,
        ),
    ]


def _build_trace_meta(
    *,
    replay_path: Path,
    replay: Replay,
    tick_rows: list[TickRecord],
    impl: Literal["python", "zig"],
) -> TraceMeta:
    tick_start = min((row.tick_index for row in tick_rows), default=-1)
    tick_end = max((row.tick_index for row in tick_rows), default=-1)
    replay_fingerprint = _build_replay_fingerprint(replay_path=replay_path, replay=replay)
    return TraceMeta(
        trace_format_version=TRACE_FORMAT_VERSION,
        trace_schema_version=TRACE_SCHEMA_VERSION,
        created_utc=datetime.now(tz=UTC).isoformat(),
        producer=TraceProducer(
            impl=str(impl),
            impl_version="",
            platform=str(platform.system()),
            arch=str(platform.machine()),
        ),
        source=_source_from_replay_fingerprint(replay_fingerprint),
        tick_range=TraceTickRange(
            start_tick=tick_start,
            end_tick=tick_end,
            tick_count=len(tick_rows),
        ),
        status=replay.header.status,
    )


def _record_replay_to_trace_python(
    *,
    replay_path: Path,
    out_path: Path,
    pre_tick_rand_draws: int = 0,
) -> TraceSummary:
    replay = load_replay_file(replay_path)

    replay_tick_count = len(replay.ticks)
    checkpoint_ticks = set(range(replay_tick_count))
    checkpoints: list[ReplayCheckpoint] = []

    entity_samples_by_tick: dict[int, EntitySamplesSnapshot] = {}
    sim_state_by_tick: dict[int, SimStateSnapshot] = {}
    rng_stream_by_tick: dict[int, list[RngStreamRow]] = {}
    timing_samples_by_tick: dict[int, list[TimingSampleRow]] = {}
    creature_state = _EntityGenerationState()
    projectile_state = _EntityGenerationState()
    secondary_state = _EntityGenerationState()
    bonus_state = _EntityGenerationState()

    # Native burns rand draws outside the hooked gameplay stream before each
    # tick (the discarded per-frame `crt_rand()` in `game_frame_update`
    # 0x0040c1c0, call site 0x0040cac7). Modeling them as pre-tick draws keeps
    # the in-tick rng stream aligned with frida_original captures.
    driver = build_verify_playback_driver(
        replay,
        max_ticks=None,
        trace_rng=True,
        strict_rng_trace=True,
        inter_tick_rand_draws=max(0, int(pre_tick_rand_draws)),
        inter_tick_rand_draws_by_tick=({} if int(pre_tick_rand_draws) > 0 else None),
    )

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
            tick_index = int(tick_result.source_tick.tick_index)
            if tick_index in checkpoint_ticks:
                checkpoints.append(driver.build_checkpoint(tick_result=tick_result))
            entity_samples_by_tick[tick_index] = _entity_samples_for_world(
                world,
                creature_state=creature_state,
                projectile_state=projectile_state,
                secondary_state=secondary_state,
                bonus_state=bonus_state,
            )
            sim_state_by_tick[tick_index] = _sim_state_from_world(world, replay=replay)

        def rng_trace(self, tick_result: TickResult, draws: tuple[RngTraceDraw, ...]) -> None:
            rng_stream_by_tick[int(tick_result.source_tick.tick_index)] = _rng_stream_from_draws(list(draws))

    driver.run(
        observer=_ReplayRecordObserver(),
    )

    tick_rows: list[TickRecord] = []
    replay_dt_rows = [ftol_ms_i32(tick.dt) for tick in replay.ticks]
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
            checkpoint=checkpoint,
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
                mode_id=int(replay.header.game_mode_id),
                channels=channels,
            ),
        )

    meta = _build_trace_meta(
        replay_path=replay_path,
        replay=replay,
        tick_rows=tick_rows,
        impl="python",
    )
    return write_trace(
        out_path,
        meta=meta,
        ticks=tick_rows,
        chunk_ticks=_TRACE_CHUNK_TICKS,
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


def _record_replay_to_trace_zig(
    *,
    replay_path: Path,
    out_path: Path,
) -> tuple[TraceSummary, list[str]]:
    build_run = _run_process(["zig", "build"], cwd=_ZIG_ROOT)
    if int(build_run.returncode) != 0:
        raise ValueError(
            f"zig build failed: exit={int(build_run.returncode)} detail={_command_detail(build_run)}",
        )

    warnings: list[str] = []
    verify_cmd = [
        str(_ZIG_BIN),
        "replay",
        "verify",
        str(replay_path),
        "--debug-trace-cdt",
        str(out_path),
        "--format",
        "json",
    ]
    verify_run = _run_process(verify_cmd, cwd=_REPO_ROOT)
    if not out_path.is_file():
        raise ValueError(
            "zig trace generation failed: replay verify did not produce CDT output; "
            f"exit={int(verify_run.returncode)} detail={_command_detail(verify_run)}",
        )
    if int(verify_run.returncode) != 0:
        warning = f"warning: zig replay verify exited {int(verify_run.returncode)}; continuing with emitted trace"
        stderr = str(verify_run.stderr).strip()
        if stderr:
            warning = f"{warning}: {stderr.splitlines()[0]}"
        warnings.append(warning)

    try:
        with TraceReader(out_path) as trace:
            decoded_tick_count = sum(1 for _ in trace.iter_ticks())
            if int(decoded_tick_count) != int(trace.footer.tick_count):
                raise TraceError(
                    "zig trace validation failed to decode all tick payloads: "
                    f"decoded={int(decoded_tick_count)} footer={int(trace.footer.tick_count)}",
                )
            summary = TraceSummary(meta=trace.meta, footer=trace.footer)
    except TraceError as exc:
        raise ValueError(f"zig trace validation failed: {exc}") from exc
    return summary, warnings


def record_replay_to_trace(
    *,
    replay_path: Path,
    out_path: Path,
    impl: Literal["python", "zig"] = "python",
    warnings_out: list[str] | None = None,
    pre_tick_rand_draws: int = 0,
) -> TraceSummary:
    replay_path = Path(replay_path)
    out_path = Path(out_path)
    if warnings_out is None:
        warnings_out = []
    if str(impl) == "python":
        summary = _record_replay_to_trace_python(
            replay_path=replay_path,
            out_path=out_path,
            pre_tick_rand_draws=pre_tick_rand_draws,
        )
        return summary
    if int(pre_tick_rand_draws) > 0:
        raise ValueError(f"pre_tick_rand_draws is only supported for the python recorder, not {impl!r}")
    if str(impl) == "zig":
        summary, warnings = _record_replay_to_trace_zig(
            replay_path=replay_path,
            out_path=out_path,
        )
        warnings_out.extend(warnings)
        return summary
    raise ValueError(f"unsupported dbg record impl: {impl!r}")
