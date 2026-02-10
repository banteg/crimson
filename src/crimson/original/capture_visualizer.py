from __future__ import annotations

import argparse
import math
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import pyray as rl

from grim.app import run_view
from grim.assets import find_paq_path
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font
from grim.geom import Vec2

from crimson.game_modes import GameMode
from crimson.gameplay import PlayerInput
from crimson.original.capture import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    build_capture_dt_frame_ms_i32_overrides,
    build_capture_dt_frame_overrides,
    capture_bootstrap_payload_from_event_payload,
    convert_capture_to_replay,
    load_capture,
)
from crimson.original.schema import CaptureTick
from crimson.replay.types import Replay, UnknownEvent, unpack_input_flags, unpack_packed_player_input
from crimson.sim.runners.common import (
    build_damage_scale_by_type,
    build_empty_fx_queues,
    reset_players,
    status_from_snapshot,
)
from crimson.sim.runners.survival import (
    _apply_tick_events,
    _partition_tick_events,
    _resolve_dt_frame,
)
from crimson.sim.sessions import SurvivalDeterministicSession
from crimson.sim.world_state import WorldState
from crimson.paths import default_runtime_dir


_CAPTURE_TRACE_COLOR = rl.Color(74, 205, 255, 150)
_REWRITE_TRACE_COLOR = rl.Color(255, 143, 70, 150)
_CAPTURE_HITBOX_COLOR = rl.Color(84, 230, 170, 220)
_REWRITE_HITBOX_COLOR = rl.Color(255, 130, 130, 220)
_CAPTURE_PLAYER_COLOR = rl.Color(84, 220, 255, 235)
_REWRITE_PLAYER_COLOR = rl.Color(255, 190, 90, 235)
_DIVERGENCE_LINE_COLOR = rl.Color(255, 240, 130, 220)
_BACKGROUND_COLOR = rl.Color(14, 16, 21, 255)
_GRID_COLOR = rl.Color(36, 40, 50, 255)
_TEXT_COLOR = rl.Color(240, 242, 248, 255)
_TEXT_DIM_COLOR = rl.Color(185, 190, 202, 255)
_PROJECTILE_TRACE_RESET_DIST = 80.0
_MIN_PLAYBACK_SPEED_EXP = -4
_MAX_PLAYBACK_SPEED_EXP = 4


@dataclass(slots=True)
class _EntityDraw:
    x: float
    y: float
    radius: float
    active: bool = True
    filled: bool = False


@dataclass(slots=True)
class _TraceHistory:
    max_age_ticks: int
    capture: deque[tuple[int, float, float]] = field(default_factory=deque)
    rewrite: deque[tuple[int, float, float]] = field(default_factory=deque)
    capture_last_tick: int | None = None
    rewrite_last_tick: int | None = None
    capture_was_active: bool = False
    rewrite_was_active: bool = False


@dataclass(slots=True)
class _DetachedTrace:
    points: deque[tuple[int, float, float]]
    max_age_ticks: int
    last_active_tick: int


@dataclass(slots=True)
class _FrameSnapshot:
    tick_index: int
    capture_players: dict[int, _EntityDraw]
    rewrite_players: dict[int, _EntityDraw]
    capture_creatures: dict[int, _EntityDraw]
    rewrite_creatures: dict[int, _EntityDraw]
    capture_projectiles: dict[int, _EntityDraw]
    rewrite_projectiles: dict[int, _EntityDraw]
    capture_secondary: dict[int, _EntityDraw]
    rewrite_secondary: dict[int, _EntityDraw]
    capture_sample_counts: dict[str, int]


def _finite(value: object, default: float = 0.0) -> float:
    if isinstance(value, bool):
        out = float(int(value))
    elif isinstance(value, (int, float)):
        out = float(value)
    elif isinstance(value, str):
        try:
            out = float(value)
        except ValueError:
            return float(default)
    else:
        return float(default)
    return out if math.isfinite(out) else float(default)


def _norm_radius(value: float, *, default: float = 4.0) -> float:
    radius = abs(float(value))
    if not math.isfinite(radius) or radius <= 0.0:
        return float(default)
    return max(1.0, radius)


def _load_capture_events(replay: Replay) -> tuple[dict[int, list[object]], bool]:
    events_by_tick: dict[int, list[object]] = {}
    original_capture_replay = False
    for event in replay.events:
        if isinstance(event, UnknownEvent) and str(event.kind) == CAPTURE_BOOTSTRAP_EVENT_KIND:
            original_capture_replay = True
            payload = capture_bootstrap_payload_from_event_payload(list(event.payload))
            if not isinstance(payload, dict):
                continue
        events_by_tick.setdefault(int(event.tick_index), []).append(event)
    return events_by_tick, original_capture_replay


class CaptureVisualizerView:
    def __init__(
        self,
        *,
        capture_path: Path,
        assets_dir: Path | None,
        start_tick: int,
        end_tick: int | None,
        playback_speed: float,
        player_trace_length: int,
        creature_trace_length: int,
        projectile_trace_length: int,
        inter_tick_rand_draws: int,
        seed: int | None,
    ) -> None:
        self._capture = load_capture(Path(capture_path))
        self._replay = convert_capture_to_replay(self._capture, seed=seed)
        self._mode_id = int(self._replay.header.game_mode_id)
        if self._mode_id != int(GameMode.SURVIVAL):
            raise ValueError(
                f"capture visualizer supports survival mode only (got mode={self._mode_id})"
            )

        self._rows: list[CaptureTick] = sorted(
            self._capture.ticks,
            key=lambda row: int(row.tick_index),
        )
        if not self._rows:
            raise ValueError("capture has no tick rows")

        max_tick = int(self._rows[-1].tick_index)
        self._start_tick = max(0, int(start_tick))
        req_end_tick = max_tick if end_tick is None else max(0, int(end_tick))
        self._end_tick = min(max_tick, int(req_end_tick))
        if self._end_tick < self._start_tick:
            raise ValueError(
                f"end_tick must be >= start_tick (got start={self._start_tick}, end={self._end_tick})"
            )

        self._visible_start_idx = next(
            (idx for idx, row in enumerate(self._rows) if int(row.tick_index) >= int(self._start_tick)),
            len(self._rows),
        )
        self._visible_end_idx = max(
            idx
            for idx, row in enumerate(self._rows)
            if int(self._start_tick) <= int(row.tick_index) <= int(self._end_tick)
        )
        if self._visible_start_idx >= len(self._rows):
            raise ValueError(
                f"start_tick={self._start_tick} is beyond last capture tick {max_tick}"
            )

        self._world_size = float(self._replay.header.world_size)
        if self._world_size <= 0.0 or not math.isfinite(self._world_size):
            self._world_size = 1024.0
        self._tick_rate = max(1, int(self._replay.header.tick_rate))
        self._step_interval = 1.0 / float(self._tick_rate)
        self._playback_speed = max(
            float(2.0**_MIN_PLAYBACK_SPEED_EXP),
            min(float(playback_speed), float(2.0**_MAX_PLAYBACK_SPEED_EXP)),
        )
        self._player_trace_length = max(1, int(player_trace_length))
        self._creature_trace_length = max(1, int(creature_trace_length))
        self._projectile_trace_length = max(1, int(projectile_trace_length))
        self._inter_tick_rand_draws = max(0, int(inter_tick_rand_draws))
        self._assets_root = self._resolve_assets_root(assets_dir)
        self._missing_assets: list[str] = []
        self._small: SmallFontData | None = None

        self._events_by_tick, self._original_capture_replay = _load_capture_events(self._replay)
        self._dt_frame_overrides = build_capture_dt_frame_overrides(
            self._capture,
            tick_rate=int(self._tick_rate),
        )
        self._dt_frame_ms_i32_overrides = build_capture_dt_frame_ms_i32_overrides(self._capture)

        outside_by_tick: dict[int, int] = {}
        for row in self._rows:
            calls = int(row.rng.outside_before_calls)
            if calls < 0:
                continue
            outside_by_tick[int(row.tick_index)] = int(calls)
        if outside_by_tick:
            first_tick = min(outside_by_tick)
            # The inferred seed aligns with the first sampled capture row.
            outside_by_tick[int(first_tick)] = 0
        self._outside_draws_by_tick = outside_by_tick if outside_by_tick else None

        self._row_cursor = -1
        self._snapshot: _FrameSnapshot | None = None
        self._trace_histories: dict[str, _TraceHistory] = {}
        self._detached_capture_traces: list[_DetachedTrace] = []
        self._detached_rewrite_traces: list[_DetachedTrace] = []
        self._accumulator = 0.0
        self._paused = False
        self._show_traces = True
        self._show_divergence = True
        self._show_capture_hitboxes = True
        self._show_rewrite_hitboxes = True
        self._close_requested = False

        self._world: WorldState | None = None
        self._session: SurvivalDeterministicSession | None = None
        self._bootstrap_world()

    def should_close(self) -> bool:
        return bool(self._close_requested)

    def _bootstrap_world(self) -> None:
        world = WorldState.build(
            world_size=float(self._world_size),
            demo_mode_active=False,
            hardcore=bool(self._replay.header.hardcore),
            difficulty_level=int(self._replay.header.difficulty_level),
            preserve_bugs=bool(self._replay.header.preserve_bugs),
        )
        reset_players(
            world.players,
            world_size=float(self._world_size),
            player_count=int(self._replay.header.player_count),
        )
        world.state.status = status_from_snapshot(
            quest_unlock_index=int(self._replay.header.status.quest_unlock_index),
            quest_unlock_index_full=int(self._replay.header.status.quest_unlock_index_full),
            weapon_usage_counts=self._replay.header.status.weapon_usage_counts,
        )
        world.state.rng.srand(int(self._replay.header.seed))

        fx_queue, fx_queue_rotated = build_empty_fx_queues()
        session = SurvivalDeterministicSession(
            world=world,
            world_size=float(self._world_size),
            damage_scale_by_type=build_damage_scale_by_type(),
            fx_queue=fx_queue,
            fx_queue_rotated=fx_queue_rotated,
            detail_preset=5,
            fx_toggle=0,
            game_tune_started=False,
            clear_fx_queues_each_tick=True,
        )

        self._world = world
        self._session = session
        self._row_cursor = -1
        self._snapshot = None
        self._trace_histories.clear()
        self._detached_capture_traces.clear()
        self._detached_rewrite_traces.clear()
        self._accumulator = 0.0

        for idx in range(0, int(self._visible_start_idx)):
            self._step_row(int(idx), record=False)
        if self._visible_start_idx <= self._visible_end_idx:
            self._step_row(int(self._visible_start_idx), record=True)
            self._row_cursor = int(self._visible_start_idx)

    @staticmethod
    def _resolve_assets_root(assets_dir: Path | None) -> Path:
        def _has_small_font_assets(root: Path) -> bool:
            if find_paq_path(root) is not None:
                return True
            widths_path = root / "crimson" / "load" / "smallFnt.dat"
            atlas_png = root / "crimson" / "load" / "smallWhite.png"
            atlas_tga = root / "crimson" / "load" / "smallWhite.tga"
            return bool(widths_path.is_file() and (atlas_png.is_file() or atlas_tga.is_file()))

        if assets_dir is not None:
            return Path(assets_dir)
        runtime_dir = default_runtime_dir()
        local_assets = Path("artifacts") / "assets"
        if _has_small_font_assets(runtime_dir):
            return runtime_dir
        if _has_small_font_assets(local_assets):
            return local_assets
        if runtime_dir.is_dir():
            return runtime_dir
        if local_assets.is_dir():
            return local_assets
        return runtime_dir

    def open(self) -> None:
        self._missing_assets.clear()
        try:
            self._small = load_small_font(self._assets_root, self._missing_assets)
        except Exception:
            self._small = None

    def close(self) -> None:
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def _build_inputs_from_replay(self, tick_index: int) -> list[PlayerInput]:
        player_count = max(1, int(self._replay.header.player_count))
        if 0 <= int(tick_index) < len(self._replay.inputs):
            packed_tick = self._replay.inputs[int(tick_index)]
        else:
            packed_tick = []
        out: list[PlayerInput] = []

        for player_index in range(player_count):
            if int(player_index) < len(packed_tick):
                mx, my, ax, ay, flags = unpack_packed_player_input(packed_tick[int(player_index)])
                fire_down, fire_pressed, reload_pressed = unpack_input_flags(int(flags))
            else:
                mx = 0.0
                my = 0.0
                ax = 0.0
                ay = 0.0
                fire_down = False
                fire_pressed = False
                reload_pressed = False
            out.append(
                PlayerInput(
                    move=Vec2(float(mx), float(my)),
                    aim=Vec2(float(ax), float(ay)),
                    fire_down=bool(fire_down),
                    fire_pressed=bool(fire_pressed),
                    reload_pressed=bool(reload_pressed),
                    move_forward_pressed=None,
                    move_backward_pressed=None,
                    turn_left_pressed=None,
                    turn_right_pressed=None,
                )
            )

        return out

    def _step_row(self, row_index: int, *, record: bool) -> None:
        if self._world is None or self._session is None:
            return
        row = self._rows[int(row_index)]
        tick_index = int(row.tick_index)

        if self._outside_draws_by_tick is not None:
            draws = self._outside_draws_by_tick.get(int(tick_index))
            if draws is None:
                draws = int(self._inter_tick_rand_draws)
            for _ in range(max(0, int(draws))):
                self._world.state.rng.rand()

        dt_tick = _resolve_dt_frame(
            tick_index=int(tick_index),
            default_dt_frame=float(self._step_interval),
            dt_frame_overrides=self._dt_frame_overrides,
        )
        dt_tick_ms_i32 = self._dt_frame_ms_i32_overrides.get(int(tick_index))

        tick_events = self._events_by_tick.get(int(tick_index), [])
        pre_step_events, post_step_events = _partition_tick_events(
            tick_events,
            defer_menu_open=bool(self._original_capture_replay),
        )
        _apply_tick_events(
            pre_step_events,
            tick_index=int(tick_index),
            dt_frame=float(dt_tick),
            world=self._world,
            strict_events=False,
        )
        inputs = self._build_inputs_from_replay(tick_index)
        self._session.step_tick(
            dt_frame=float(dt_tick),
            dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
            inputs=inputs,
            trace_rng=False,
        )

        if post_step_events:
            _apply_tick_events(
                post_step_events,
                tick_index=int(tick_index),
                dt_frame=float(dt_tick),
                world=self._world,
                strict_events=False,
            )

        if self._outside_draws_by_tick is None:
            draws = max(0, int(self._inter_tick_rand_draws))
            for _ in range(draws):
                self._world.state.rng.rand()

        if record:
            self._snapshot = self._build_snapshot(row)
            self._append_traces(self._snapshot)

    def _build_snapshot(self, row: CaptureTick) -> _FrameSnapshot:
        assert self._world is not None

        capture_players: dict[int, _EntityDraw] = {}
        rewrite_players: dict[int, _EntityDraw] = {}
        player_count = max(len(row.checkpoint.players), len(self._world.players))
        for idx in range(player_count):
            if idx < len(row.checkpoint.players):
                cap = row.checkpoint.players[idx]
                capture_players[int(idx)] = _EntityDraw(
                    x=_finite(cap.pos.x),
                    y=_finite(cap.pos.y),
                    radius=12.0,
                    active=True,
                )
            if idx < len(self._world.players):
                rw = self._world.players[idx]
                rewrite_players[int(idx)] = _EntityDraw(
                    x=_finite(rw.pos.x),
                    y=_finite(rw.pos.y),
                    radius=_norm_radius(float(rw.size) * 0.5, default=12.0),
                    active=bool(rw.health > 0.0),
                )

        capture_creatures: dict[int, _EntityDraw] = {}
        capture_projectiles: dict[int, _EntityDraw] = {}
        capture_secondary: dict[int, _EntityDraw] = {}
        samples = row.samples
        if samples is not None:
            for sample in samples.creatures:
                hitbox_radius = float(sample.hitbox_size) * 0.5
                capture_creatures[int(sample.index)] = _EntityDraw(
                    x=_finite(sample.pos.x),
                    y=_finite(sample.pos.y),
                    radius=_norm_radius(float(hitbox_radius), default=8.0),
                    active=bool(int(sample.active) != 0),
                    filled=bool(math.isfinite(hitbox_radius) and float(hitbox_radius) < 0.0),
                )
            for sample in samples.projectiles:
                hit_radius = float(sample.hit_radius)
                capture_projectiles[int(sample.index)] = _EntityDraw(
                    x=_finite(sample.pos.x),
                    y=_finite(sample.pos.y),
                    radius=_norm_radius(float(hit_radius), default=3.0),
                    active=bool(int(sample.active) != 0),
                    filled=bool(math.isfinite(hit_radius) and float(hit_radius) < 0.0),
                )
            for sample in samples.secondary_projectiles:
                capture_secondary[int(sample.index)] = _EntityDraw(
                    x=_finite(sample.pos.x),
                    y=_finite(sample.pos.y),
                    radius=3.5,
                    active=bool(int(sample.active) != 0),
                )

        rewrite_creatures: dict[int, _EntityDraw] = {}
        for idx, creature in enumerate(self._world.creatures.entries):
            if not bool(creature.active):
                continue
            hitbox_radius = float(creature.hitbox_size) * 0.5
            rewrite_creatures[int(idx)] = _EntityDraw(
                x=_finite(creature.pos.x),
                y=_finite(creature.pos.y),
                radius=_norm_radius(float(hitbox_radius), default=8.0),
                active=True,
                filled=bool(math.isfinite(hitbox_radius) and float(hitbox_radius) < 0.0),
            )

        rewrite_projectiles: dict[int, _EntityDraw] = {}
        for idx, projectile in enumerate(self._world.state.projectiles.entries):
            if not bool(projectile.active):
                continue
            hit_radius = float(projectile.hit_radius)
            rewrite_projectiles[int(idx)] = _EntityDraw(
                x=_finite(projectile.pos.x),
                y=_finite(projectile.pos.y),
                radius=_norm_radius(float(hit_radius), default=3.0),
                active=True,
                filled=bool(math.isfinite(hit_radius) and float(hit_radius) < 0.0),
            )

        rewrite_secondary: dict[int, _EntityDraw] = {}
        for idx, projectile in enumerate(self._world.state.secondary_projectiles.entries):
            if not bool(projectile.active):
                continue
            rewrite_secondary[int(idx)] = _EntityDraw(
                x=_finite(projectile.pos.x),
                y=_finite(projectile.pos.y),
                radius=3.5,
                active=True,
            )

        sample_counts = {
            "creatures": int(len(capture_creatures)),
            "projectiles": int(len(capture_projectiles)),
            "secondary_projectiles": int(len(capture_secondary)),
        }
        return _FrameSnapshot(
            tick_index=int(row.tick_index),
            capture_players=capture_players,
            rewrite_players=rewrite_players,
            capture_creatures=capture_creatures,
            rewrite_creatures=rewrite_creatures,
            capture_projectiles=capture_projectiles,
            rewrite_projectiles=rewrite_projectiles,
            capture_secondary=capture_secondary,
            rewrite_secondary=rewrite_secondary,
            capture_sample_counts=sample_counts,
        )

    def _trace_length_for_key(self, key: str) -> int:
        if key.startswith("p:"):
            return int(self._player_trace_length)
        if key.startswith("c:"):
            return int(self._creature_trace_length)
        # Both projectile pools (primary + secondary) use the projectile horizon.
        return int(self._projectile_trace_length)

    @staticmethod
    def _is_projectile_trace_key(key: str) -> bool:
        return key.startswith("pr:") or key.startswith("spr:")

    @staticmethod
    def _jump_distance_sq(
        points: deque[tuple[int, float, float]],
        *,
        x: float,
        y: float,
    ) -> float:
        if not points:
            return 0.0
        _, prev_x, prev_y = points[-1]
        dx = float(x) - float(prev_x)
        dy = float(y) - float(prev_y)
        return float(dx * dx + dy * dy)

    @staticmethod
    def _detach_points(
        out: list[_DetachedTrace],
        *,
        points: deque[tuple[int, float, float]],
        max_age_ticks: int,
        last_active_tick: int | None,
    ) -> None:
        if not points:
            return
        last_tick = int(last_active_tick) if last_active_tick is not None else int(points[-1][0])
        out.append(
            _DetachedTrace(
                points=deque(points, maxlen=max(1, int(max_age_ticks))),
                max_age_ticks=max(1, int(max_age_ticks)),
                last_active_tick=int(last_tick),
            )
        )

    @staticmethod
    def _prune_trace_points(
        points: deque[tuple[int, float, float]],
        *,
        current_tick: int,
        max_age_ticks: int,
    ) -> None:
        if not points:
            return
        min_tick = int(current_tick) - max(1, int(max_age_ticks)) + 1
        while points and int(points[0][0]) < int(min_tick):
            points.popleft()

    def _prune_traces(self, *, current_tick: int) -> None:
        if not self._trace_histories:
            return
        stale_keys: list[str] = []
        for key, trace in self._trace_histories.items():
            self._prune_trace_points(
                trace.capture,
                current_tick=int(current_tick),
                max_age_ticks=int(trace.max_age_ticks),
            )
            self._prune_trace_points(
                trace.rewrite,
                current_tick=int(current_tick),
                max_age_ticks=int(trace.max_age_ticks),
            )
            if not trace.capture and not trace.rewrite:
                stale_keys.append(str(key))
        for key in stale_keys:
            self._trace_histories.pop(str(key), None)
        self._detached_capture_traces = [
            trace
            for trace in self._detached_capture_traces
            if self._prune_detached_trace(trace, current_tick=int(current_tick))
        ]
        self._detached_rewrite_traces = [
            trace
            for trace in self._detached_rewrite_traces
            if self._prune_detached_trace(trace, current_tick=int(current_tick))
        ]

    def _prune_detached_trace(self, trace: _DetachedTrace, *, current_tick: int) -> bool:
        self._prune_trace_points(
            trace.points,
            current_tick=int(current_tick),
            max_age_ticks=int(trace.max_age_ticks),
        )
        if not trace.points:
            return False
        if int(current_tick) - int(trace.last_active_tick) > int(trace.max_age_ticks):
            return False
        return True

    def _append_trace_point(
        self,
        key: str,
        *,
        tick_index: int,
        capture: _EntityDraw | None,
        rewrite: _EntityDraw | None,
    ) -> None:
        trace = self._trace_histories.get(key)
        if trace is None:
            trace_length = int(self._trace_length_for_key(key))
            trace = _TraceHistory(
                max_age_ticks=int(trace_length),
                capture=deque(maxlen=trace_length),
                rewrite=deque(maxlen=trace_length),
            )
            self._trace_histories[key] = trace
        tick_index = int(tick_index)
        projectile_key = bool(self._is_projectile_trace_key(key))
        capture_active = capture is not None and bool(capture.active)
        if capture_active and capture is not None:
            capture_x = float(capture.x)
            capture_y = float(capture.y)
            reset_capture = not bool(trace.capture_was_active)
            if trace.capture_last_tick is not None and int(tick_index) - int(trace.capture_last_tick) > 1:
                # Prevent slot reuse/inactivity gaps from stitching two different lifetimes.
                reset_capture = True
            if projectile_key and trace.capture:
                jump_sq = self._jump_distance_sq(trace.capture, x=float(capture_x), y=float(capture_y))
                if jump_sq > float(_PROJECTILE_TRACE_RESET_DIST * _PROJECTILE_TRACE_RESET_DIST):
                    reset_capture = True
            if reset_capture:
                self._detach_points(
                    self._detached_capture_traces,
                    points=trace.capture,
                    max_age_ticks=int(trace.max_age_ticks),
                    last_active_tick=trace.capture_last_tick,
                )
                trace.capture.clear()
            trace.capture.append((int(tick_index), float(capture_x), float(capture_y)))
            trace.capture_last_tick = int(tick_index)
        trace.capture_was_active = bool(capture_active)

        rewrite_active = rewrite is not None and bool(rewrite.active)
        if rewrite_active and rewrite is not None:
            rewrite_x = float(rewrite.x)
            rewrite_y = float(rewrite.y)
            reset_rewrite = not bool(trace.rewrite_was_active)
            if trace.rewrite_last_tick is not None and int(tick_index) - int(trace.rewrite_last_tick) > 1:
                reset_rewrite = True
            if projectile_key and trace.rewrite:
                jump_sq = self._jump_distance_sq(trace.rewrite, x=float(rewrite_x), y=float(rewrite_y))
                if jump_sq > float(_PROJECTILE_TRACE_RESET_DIST * _PROJECTILE_TRACE_RESET_DIST):
                    reset_rewrite = True
            if reset_rewrite:
                self._detach_points(
                    self._detached_rewrite_traces,
                    points=trace.rewrite,
                    max_age_ticks=int(trace.max_age_ticks),
                    last_active_tick=trace.rewrite_last_tick,
                )
                trace.rewrite.clear()
            trace.rewrite.append((int(tick_index), float(rewrite_x), float(rewrite_y)))
            trace.rewrite_last_tick = int(tick_index)
        trace.rewrite_was_active = bool(rewrite_active)

    def _append_traces(self, snapshot: _FrameSnapshot) -> None:
        tick_index = int(snapshot.tick_index)
        self._prune_traces(current_tick=int(tick_index))
        for idx in sorted(set(snapshot.capture_players) | set(snapshot.rewrite_players)):
            self._append_trace_point(
                f"p:{int(idx)}",
                tick_index=int(tick_index),
                capture=snapshot.capture_players.get(int(idx)),
                rewrite=snapshot.rewrite_players.get(int(idx)),
            )
        for idx in sorted(set(snapshot.capture_creatures) | set(snapshot.rewrite_creatures)):
            self._append_trace_point(
                f"c:{int(idx)}",
                tick_index=int(tick_index),
                capture=snapshot.capture_creatures.get(int(idx)),
                rewrite=snapshot.rewrite_creatures.get(int(idx)),
            )
        for idx in sorted(set(snapshot.capture_projectiles) | set(snapshot.rewrite_projectiles)):
            self._append_trace_point(
                f"pr:{int(idx)}",
                tick_index=int(tick_index),
                capture=snapshot.capture_projectiles.get(int(idx)),
                rewrite=snapshot.rewrite_projectiles.get(int(idx)),
            )
        for idx in sorted(set(snapshot.capture_secondary) | set(snapshot.rewrite_secondary)):
            self._append_trace_point(
                f"spr:{int(idx)}",
                tick_index=int(tick_index),
                capture=snapshot.capture_secondary.get(int(idx)),
                rewrite=snapshot.rewrite_secondary.get(int(idx)),
            )

    def _advance_one_tick(self) -> bool:
        if self._row_cursor >= self._visible_end_idx:
            return False
        next_idx = self._row_cursor + 1
        if next_idx < self._visible_start_idx:
            next_idx = int(self._visible_start_idx)
        if next_idx > self._visible_end_idx:
            return False
        self._step_row(int(next_idx), record=True)
        self._row_cursor = int(next_idx)
        return True

    def _step_playback_speed(self, *, faster: bool) -> None:
        min_exp = int(_MIN_PLAYBACK_SPEED_EXP)
        max_exp = int(_MAX_PLAYBACK_SPEED_EXP)
        min_speed = float(2.0**min_exp)
        max_speed = float(2.0**max_exp)
        speed = float(self._playback_speed)
        if not math.isfinite(speed) or speed <= 0.0:
            speed = 1.0
        speed = max(float(min_speed), min(float(speed), float(max_speed)))
        log_speed = float(math.log2(speed))

        if faster:
            exp = int(math.ceil(log_speed - 1e-12))
            if math.isclose(speed, float(2.0**exp), rel_tol=1e-9, abs_tol=1e-12):
                exp += 1
        else:
            exp = int(math.floor(log_speed + 1e-12))
            if math.isclose(speed, float(2.0**exp), rel_tol=1e-9, abs_tol=1e-12):
                exp -= 1

        exp = max(min_exp, min(max_exp, int(exp)))
        self._playback_speed = float(2.0**exp)

    def _handle_input(self) -> None:
        if rl.is_key_pressed(rl.KeyboardKey.KEY_SPACE):
            self._paused = not bool(self._paused)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_R):
            self._bootstrap_world()
            self._paused = True
        if rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT) and self._paused:
            self._advance_one_tick()
        if rl.is_key_pressed(rl.KeyboardKey.KEY_LEFT_BRACKET):
            self._step_playback_speed(faster=False)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_SLASH) or rl.is_key_pressed(rl.KeyboardKey.KEY_RIGHT_BRACKET):
            self._step_playback_speed(faster=True)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_T):
            self._show_traces = not bool(self._show_traces)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_L):
            self._show_divergence = not bool(self._show_divergence)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_C):
            self._show_capture_hitboxes = not bool(self._show_capture_hitboxes)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_V):
            self._show_rewrite_hitboxes = not bool(self._show_rewrite_hitboxes)
        if rl.is_key_pressed(rl.KeyboardKey.KEY_ESCAPE):
            self._close_requested = True

    def update(self, dt: float) -> None:
        self._handle_input()
        if self._paused:
            return
        if self._row_cursor >= self._visible_end_idx:
            return
        self._accumulator += max(0.0, float(dt)) * float(self._playback_speed)
        while self._accumulator >= float(self._step_interval):
            self._accumulator -= float(self._step_interval)
            if not self._advance_one_tick():
                self._paused = True
                break

    def _world_to_screen(self, *, x: float, y: float, width: int, height: int) -> tuple[int, int]:
        scale_x = float(width) / float(self._world_size)
        scale_y = float(height) / float(self._world_size)
        sx = int(round(float(x) * scale_x))
        sy = int(round(float(y) * scale_y))
        return sx, sy

    def _radius_to_screen(self, radius: float, *, width: int, height: int) -> float:
        scale = min(float(width), float(height)) / float(self._world_size)
        return max(1.0, float(radius) * scale)

    def _draw_trace(
        self,
        points: deque[tuple[int, float, float]],
        *,
        last_active_tick: int | None,
        current_tick: int,
        max_age_ticks: int,
        width: int,
        height: int,
        color: rl.Color,
    ) -> None:
        if len(points) < 2:
            return
        point_list = list(points)
        inactive_progress = 0.0
        if last_active_tick is not None and int(current_tick) > int(last_active_tick):
            inactive_age = int(current_tick) - int(last_active_tick)
            inactive_progress = min(1.0, float(inactive_age) / float(max(1, int(max_age_ticks))))
        if inactive_progress >= 1.0:
            return

        start_pos = float(inactive_progress) * float(len(point_list) - 1)
        start_idx = int(math.floor(start_pos))
        start_frac = float(start_pos) - float(start_idx)
        if start_idx >= len(point_list) - 1:
            return

        draw_points: list[tuple[int, float, float]]
        if start_frac > 0.0:
            tick0, x0, y0 = point_list[start_idx]
            tick1, x1, y1 = point_list[start_idx + 1]
            inv = 1.0 - float(start_frac)
            interp_tick = int(round(float(tick0) * inv + float(tick1) * float(start_frac)))
            interp_x = float(x0) * inv + float(x1) * float(start_frac)
            interp_y = float(y0) * inv + float(y1) * float(start_frac)
            draw_points = [(int(interp_tick), float(interp_x), float(interp_y))]
            draw_points.extend(point_list[start_idx + 1 :])
        else:
            draw_points = point_list[start_idx:]

        if len(draw_points) < 2:
            return

        inactive_alpha_scale = 1.0 - float(inactive_progress)
        _, prev_x, prev_y = draw_points[0]
        for point_tick, x, y in draw_points[1:]:
            x0, y0 = self._world_to_screen(x=float(prev_x), y=float(prev_y), width=width, height=height)
            x1, y1 = self._world_to_screen(x=float(x), y=float(y), width=width, height=height)
            if max_age_ticks <= 1:
                age_alpha_scale = 1.0
            else:
                age_ticks = max(0, int(current_tick) - int(point_tick))
                age_alpha_scale = 1.0 - min(1.0, float(age_ticks) / float(max_age_ticks - 1))
            alpha_scale = float(age_alpha_scale) * float(inactive_alpha_scale)
            alpha = int(round(float(color.a) * max(0.0, min(1.0, alpha_scale))))
            if alpha > 0:
                line_color = rl.Color(int(color.r), int(color.g), int(color.b), int(alpha))
                rl.draw_line(int(x0), int(y0), int(x1), int(y1), line_color)
            prev_x = float(x)
            prev_y = float(y)

    def _draw_entity_overlay(
        self,
        *,
        capture_map: dict[int, _EntityDraw],
        rewrite_map: dict[int, _EntityDraw],
        width: int,
        height: int,
        capture_color: rl.Color,
        rewrite_color: rl.Color,
    ) -> float:
        max_drift = 0.0
        keys = set(capture_map) | set(rewrite_map)
        for key in keys:
            capture = capture_map.get(int(key))
            rewrite = rewrite_map.get(int(key))

            if self._show_capture_hitboxes and capture is not None and bool(capture.active):
                cx, cy = self._world_to_screen(
                    x=float(capture.x), y=float(capture.y), width=width, height=height
                )
                rr = self._radius_to_screen(float(capture.radius), width=width, height=height)
                if bool(capture.filled):
                    rl.draw_circle(int(cx), int(cy), float(rr), capture_color)
                else:
                    rl.draw_circle_lines(int(cx), int(cy), float(rr), capture_color)
            if self._show_rewrite_hitboxes and rewrite is not None and bool(rewrite.active):
                rx, ry = self._world_to_screen(
                    x=float(rewrite.x), y=float(rewrite.y), width=width, height=height
                )
                rr = self._radius_to_screen(float(rewrite.radius), width=width, height=height)
                if bool(rewrite.filled):
                    rl.draw_circle(int(rx), int(ry), float(rr), rewrite_color)
                else:
                    rl.draw_circle_lines(int(rx), int(ry), float(rr), rewrite_color)

            if (
                self._show_divergence
                and capture is not None
                and rewrite is not None
                and bool(capture.active)
                and bool(rewrite.active)
            ):
                cx, cy = self._world_to_screen(
                    x=float(capture.x), y=float(capture.y), width=width, height=height
                )
                rx, ry = self._world_to_screen(
                    x=float(rewrite.x), y=float(rewrite.y), width=width, height=height
                )
                rl.draw_line(int(cx), int(cy), int(rx), int(ry), _DIVERGENCE_LINE_COLOR)
                drift = math.hypot(float(rewrite.x) - float(capture.x), float(rewrite.y) - float(capture.y))
                if drift > max_drift:
                    max_drift = drift
        return max_drift

    def _draw_ui_text(self, text: str, *, x: float, y: float, color: rl.Color, scale: float = 1.0) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, Vec2(float(x), float(y)), float(scale), color)
            return
        rl.draw_text(text, int(x), int(y), int(20 * float(scale)), color)

    def draw(self) -> None:
        width = int(rl.get_screen_width())
        height = int(rl.get_screen_height())
        rl.clear_background(_BACKGROUND_COLOR)

        for step in range(0, int(self._world_size) + 1, 128):
            x0, y0 = self._world_to_screen(x=float(step), y=0.0, width=width, height=height)
            x1, y1 = self._world_to_screen(
                x=float(step), y=float(self._world_size), width=width, height=height
            )
            rl.draw_line(int(x0), int(y0), int(x1), int(y1), _GRID_COLOR)
            x2, y2 = self._world_to_screen(x=0.0, y=float(step), width=width, height=height)
            x3, y3 = self._world_to_screen(
                x=float(self._world_size), y=float(step), width=width, height=height
            )
            rl.draw_line(int(x2), int(y2), int(x3), int(y3), _GRID_COLOR)

        snapshot = self._snapshot
        if snapshot is None:
            self._draw_ui_text("No frame snapshot", x=12.0, y=12.0, color=_TEXT_COLOR)
            return

        self._prune_traces(current_tick=int(snapshot.tick_index))
        if self._show_traces:
            for trace in self._detached_capture_traces:
                self._draw_trace(
                    trace.points,
                    last_active_tick=int(trace.last_active_tick),
                    current_tick=int(snapshot.tick_index),
                    max_age_ticks=int(trace.max_age_ticks),
                    width=width,
                    height=height,
                    color=_CAPTURE_TRACE_COLOR,
                )
            for trace in self._detached_rewrite_traces:
                self._draw_trace(
                    trace.points,
                    last_active_tick=int(trace.last_active_tick),
                    current_tick=int(snapshot.tick_index),
                    max_age_ticks=int(trace.max_age_ticks),
                    width=width,
                    height=height,
                    color=_REWRITE_TRACE_COLOR,
                )
            for trace in self._trace_histories.values():
                self._draw_trace(
                    trace.capture,
                    last_active_tick=trace.capture_last_tick,
                    current_tick=int(snapshot.tick_index),
                    max_age_ticks=int(trace.max_age_ticks),
                    width=width,
                    height=height,
                    color=_CAPTURE_TRACE_COLOR,
                )
                self._draw_trace(
                    trace.rewrite,
                    last_active_tick=trace.rewrite_last_tick,
                    current_tick=int(snapshot.tick_index),
                    max_age_ticks=int(trace.max_age_ticks),
                    width=width,
                    height=height,
                    color=_REWRITE_TRACE_COLOR,
                )

        max_player_drift = self._draw_entity_overlay(
            capture_map=snapshot.capture_players,
            rewrite_map=snapshot.rewrite_players,
            width=width,
            height=height,
            capture_color=_CAPTURE_PLAYER_COLOR,
            rewrite_color=_REWRITE_PLAYER_COLOR,
        )
        max_creature_drift = self._draw_entity_overlay(
            capture_map=snapshot.capture_creatures,
            rewrite_map=snapshot.rewrite_creatures,
            width=width,
            height=height,
            capture_color=_CAPTURE_HITBOX_COLOR,
            rewrite_color=_REWRITE_HITBOX_COLOR,
        )
        max_projectile_drift = self._draw_entity_overlay(
            capture_map=snapshot.capture_projectiles,
            rewrite_map=snapshot.rewrite_projectiles,
            width=width,
            height=height,
            capture_color=_CAPTURE_HITBOX_COLOR,
            rewrite_color=_REWRITE_HITBOX_COLOR,
        )
        max_secondary_drift = self._draw_entity_overlay(
            capture_map=snapshot.capture_secondary,
            rewrite_map=snapshot.rewrite_secondary,
            width=width,
            height=height,
            capture_color=_CAPTURE_HITBOX_COLOR,
            rewrite_color=_REWRITE_HITBOX_COLOR,
        )

        total_rows = int(self._visible_end_idx - self._visible_start_idx + 1)
        row_progress = int(max(0, self._row_cursor - self._visible_start_idx + 1))
        paused = "paused" if self._paused else "running"
        header = (
            f"tick={snapshot.tick_index}  rows={row_progress}/{total_rows}  "
            f"speed={self._playback_speed:.2f}x  {paused}"
        )
        self._draw_ui_text(header, x=16.0, y=16.0, color=_TEXT_COLOR, scale=1.0)
        self._draw_ui_text(
            "capture trace (cyan) vs rewrite trace (orange), hitbox-only overlay",
            x=16.0,
            y=34.0,
            color=_TEXT_DIM_COLOR,
            scale=1.0,
        )
        self._draw_ui_text(
            (
                "Space pause  Right step  R restart  [ slower  / faster  "
                "T traces  L divergence-lines  C capture-hitboxes  V rewrite-hitboxes  Esc close"
            ),
            x=16.0,
            y=52.0,
            color=_TEXT_DIM_COLOR,
            scale=1.0,
        )
        self._draw_ui_text(
            (
                f"samples: creatures={snapshot.capture_sample_counts['creatures']}  "
                f"projectiles={snapshot.capture_sample_counts['projectiles']}  "
                f"secondary={snapshot.capture_sample_counts['secondary_projectiles']}"
            ),
            x=16.0,
            y=70.0,
            color=_TEXT_DIM_COLOR,
            scale=1.0,
        )

        drift_text = (
            f"max drift  players={max_player_drift:.4f}  creatures={max_creature_drift:.4f}  "
            f"projectiles={max_projectile_drift:.4f}  secondary={max_secondary_drift:.4f}"
        )
        self._draw_ui_text(
            drift_text,
            x=16.0,
            y=float(max(120, height - 24)),
            color=_TEXT_COLOR,
            scale=1.0,
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Visualize capture-vs-rewrite divergence with hitbox overlays and movement traces "
            "(replay-packed sim inputs with capture overlays)."
        ),
    )
    parser.add_argument("capture", type=Path, help="capture file (.json/.json.gz)")
    parser.add_argument("--start-tick", type=int, default=0, help="first tick to display")
    parser.add_argument("--end-tick", type=int, default=None, help="last tick to display (default: capture end)")
    parser.add_argument("--seed", type=int, default=None, help="override inferred seed")
    parser.add_argument("--speed", type=float, default=1.0, help="initial playback speed multiplier")
    parser.add_argument(
        "--trace-len",
        type=int,
        default=None,
        help="legacy override: movement trace length in ticks for all entity types",
    )
    parser.add_argument("--player-trace-len", type=int, default=1200, help="player trace length in ticks")
    parser.add_argument("--creature-trace-len", type=int, default=600, help="creature trace length in ticks")
    parser.add_argument(
        "--projectile-trace-len",
        type=int,
        default=60,
        help="projectile trace length in ticks (primary + secondary)",
    )
    parser.add_argument(
        "--inter-tick-rand-draws",
        type=int,
        default=1,
        help="fallback rand draws between ticks when outside-before telemetry is missing",
    )
    parser.add_argument("--width", type=int, default=1024, help="window width")
    parser.add_argument("--height", type=int, default=1024, help="window height")
    parser.add_argument("--fps", type=int, default=60, help="window FPS cap")
    parser.add_argument(
        "--assets-dir",
        type=Path,
        default=None,
        help="assets root used to load the game small font (default: runtime dir, fallback ./artifacts/assets)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    trace_len_override = None if args.trace_len is None else max(1, int(args.trace_len))
    player_trace_len = (
        int(trace_len_override) if trace_len_override is not None else max(1, int(args.player_trace_len))
    )
    creature_trace_len = (
        int(trace_len_override) if trace_len_override is not None else max(1, int(args.creature_trace_len))
    )
    projectile_trace_len = (
        int(trace_len_override) if trace_len_override is not None else max(1, int(args.projectile_trace_len))
    )

    try:
        view = CaptureVisualizerView(
            capture_path=Path(args.capture),
            assets_dir=(None if args.assets_dir is None else Path(args.assets_dir)),
            start_tick=int(args.start_tick),
            end_tick=(None if args.end_tick is None else int(args.end_tick)),
            playback_speed=float(args.speed),
            player_trace_length=int(player_trace_len),
            creature_trace_length=int(creature_trace_len),
            projectile_trace_length=int(projectile_trace_len),
            inter_tick_rand_draws=int(args.inter_tick_rand_draws),
            seed=(None if args.seed is None else int(args.seed)),
        )
    except Exception as exc:
        print(f"capture visualize failed: {exc}")
        return 1

    run_view(
        view,
        width=max(1, int(args.width)),
        height=max(1, int(args.height)),
        title=f"Capture Visualizer — {Path(args.capture).name}",
        fps=max(1, int(args.fps)),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
