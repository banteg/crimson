from __future__ import annotations

import argparse
import math
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import pyray as rl
from raylib import defines as rd

from grim.app import run_view
from grim.assets import find_paq_path
from grim.fonts.small import SmallFontData, draw_small_text, load_small_font, measure_small_text_width
from grim.geom import Vec2

from crimson.bonuses import BonusId
from crimson.bonuses.pool import BonusEntry, bonus_label_for_entry
from crimson.game_modes import GameMode
from crimson.sim.input import PlayerInput
from crimson.original.capture import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    CAPTURE_PERK_APPLY_EVENT_KIND,
    build_capture_dt_frame_ms_i32_overrides,
    build_capture_dt_frame_overrides,
    build_capture_inter_tick_rand_draws_overrides,
    capture_bootstrap_payload_from_event_payload,
    capture_perk_apply_id_from_event_payload,
    convert_capture_to_replay,
    load_capture,
    parse_player_int_overrides,
)
from crimson.original.schema import CaptureTick
from crimson.perks import perk_label
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
from crimson.sim.world_state import WorldEvents, WorldState
from crimson.weapons import WEAPON_BY_ID
from crimson.paths import default_runtime_dir


_CAPTURE_TRACE_COLOR = rl.Color(74, 205, 255, 220)
_REWRITE_TRACE_COLOR = rl.Color(255, 143, 70, 220)
_CAPTURE_HITBOX_COLOR = rl.Color(84, 230, 170, 220)
_REWRITE_HITBOX_COLOR = rl.Color(255, 130, 130, 220)
_CAPTURE_PLAYER_COLOR = rl.Color(84, 220, 255, 235)
_REWRITE_PLAYER_COLOR = rl.Color(255, 190, 90, 235)
_CAPTURE_BONUS_COLOR = rl.Color(120, 240, 255, 225)
_REWRITE_BONUS_COLOR = rl.Color(255, 196, 120, 225)
_DIVERGENCE_LINE_COLOR = rl.Color(255, 240, 130, 220)
_BACKGROUND_COLOR = rl.Color(14, 16, 21, 255)
_GRID_COLOR = rl.Color(36, 40, 50, 255)
_TEXT_COLOR = rl.Color(240, 242, 248, 255)
_TEXT_DIM_COLOR = rl.Color(185, 190, 202, 255)
_PROJECTILE_TRACE_RESET_DIST = 80.0
_BONUS_DRAW_RADIUS = 12.0
_MIN_PLAYBACK_SPEED_EXP = -4
_MAX_PLAYBACK_SPEED_EXP = 4
_PROJECTILE_TYPE_SHOCK_CHAIN = 0x15
_PERK_PANEL_MAX_CHOICES = 5
_PERK_PANEL_MAX_COUNTS = 4
_PERK_PANEL_MAX_APPLY = 4
_SHOCK_CHAIN_HEAD_MAX = 4


@dataclass(slots=True)
class _EntityDraw:
    x: float
    y: float
    radius: float
    active: bool = True
    filled: bool = False


@dataclass(slots=True)
class _TraceLayer:
    lifetime_ticks: int
    rt: rl.RenderTexture | None = None
    fade_accum: float = 0.0


@dataclass(slots=True)
class _BonusDraw:
    x: float
    y: float
    label: str
    active: bool = True


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
    capture_bonuses: dict[int, _BonusDraw]
    rewrite_bonuses: dict[int, _BonusDraw]
    capture_sample_counts: dict[str, int]
    gameplay_lines: tuple["_GameplayHudLine", ...] = ()


@dataclass(slots=True)
class _GameplayHudLine:
    left_text: str
    left_color: rl.Color
    right_text: str = ""
    right_color: rl.Color | None = None


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


def _int_or(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            return int(default)
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return int(default)
        try:
            return int(text, 0)
        except ValueError:
            return int(default)
    return int(default)


def _bonus_timer_ms(value: float) -> int:
    ms = int(round(float(value) * 1000.0))
    return 0 if ms < 0 else int(ms)


def _format_seconds(ms: int) -> str:
    return f"{float(ms) / 1000.0:.2f}"


def _short_text(text: str, *, max_len: int = 20) -> str:
    value = str(text)
    if len(value) <= int(max_len):
        return value
    keep = max(1, int(max_len) - 3)
    return f"{value[:keep]}..."


def _secondary_samples_use_world_space(rows: list[CaptureTick], *, world_size: float) -> bool:
    min_x = float("inf")
    max_x = float("-inf")
    min_y = float("inf")
    max_y = float("-inf")
    active_count = 0
    for row in rows:
        samples = row.samples
        if samples is None:
            continue
        for sample in samples.secondary_projectiles:
            if int(sample.active) == 0:
                continue
            x = float(sample.pos.x)
            y = float(sample.pos.y)
            if not math.isfinite(x) or not math.isfinite(y):
                continue
            active_count += 1
            min_x = min(float(min_x), float(x))
            max_x = max(float(max_x), float(x))
            min_y = min(float(min_y), float(y))
            max_y = max(float(max_y), float(y))

    # Small windows may only cover local areas; avoid over-filtering sparse traces.
    if active_count < 128:
        return True

    scale = max(1.0, float(abs(world_size)))
    span_x = float(max_x) - float(min_x)
    span_y = float(max_y) - float(min_y)
    near_origin = (
        max(abs(float(min_x)), abs(float(max_x)), abs(float(min_y)), abs(float(max_y))) <= float(scale * 0.1)
    )
    collapsed_extent = float(span_x) <= float(scale * 0.1) and float(span_y) <= float(scale * 0.1)
    # Some captures store secondary "position" in local/non-world coordinates.
    # In that case showing capture-side secondary divergence is misleading.
    return not (near_origin and collapsed_extent)


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
        aim_scheme_overrides_by_player: Mapping[int, int] | None,
    ) -> None:
        self._capture = load_capture(Path(capture_path))
        self._replay = convert_capture_to_replay(
            self._capture,
            seed=seed,
            aim_scheme_overrides_by_player=aim_scheme_overrides_by_player,
        )
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
        self._capture_secondary_world_space = _secondary_samples_use_world_space(
            self._rows,
            world_size=float(self._world_size),
        )
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

        self._outside_draws_by_tick = build_capture_inter_tick_rand_draws_overrides(self._capture)

        self._row_cursor = -1
        self._snapshot: _FrameSnapshot | None = None
        self._player_traces = _TraceLayer(lifetime_ticks=int(self._player_trace_length))
        self._creature_traces = _TraceLayer(lifetime_ticks=int(self._creature_trace_length))
        self._projectile_traces = _TraceLayer(lifetime_ticks=int(self._projectile_trace_length))
        self._trace_prev_capture: dict[str, tuple[int, float, float]] = {}
        self._trace_prev_rewrite: dict[str, tuple[int, float, float]] = {}
        self._trace_rt_size: tuple[int, int] = (0, 0)
        self._trace_fade_dt = 0.0
        self._accumulator = 0.0
        self._paused = False
        self._show_help = False
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
        self._trace_prev_capture.clear()
        self._trace_prev_rewrite.clear()
        self._trace_fade_dt = 0.0
        self._clear_trace_layers()
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
        self._unload_trace_layers()
        if self._small is not None:
            rl.unload_texture(self._small.texture)
            self._small = None

    def _trace_layers(self) -> tuple[_TraceLayer, _TraceLayer, _TraceLayer]:
        return (self._player_traces, self._creature_traces, self._projectile_traces)

    def _clear_trace_layers(self) -> None:
        for layer in self._trace_layers():
            rt = layer.rt
            layer.fade_accum = 0.0
            if rt is None or int(getattr(rt, "id", 0)) <= 0:
                continue
            rl.begin_texture_mode(rt)
            rl.clear_background(rl.Color(0, 0, 0, 0))
            rl.end_texture_mode()

    def _unload_trace_layers(self) -> None:
        for layer in self._trace_layers():
            rt = layer.rt
            if rt is not None and int(getattr(rt, "id", 0)) > 0:
                rl.unload_render_texture(rt)
            layer.rt = None
            layer.fade_accum = 0.0
        self._trace_rt_size = (0, 0)

    def _ensure_trace_layers(self, *, width: int, height: int) -> None:
        width = int(max(1, width))
        height = int(max(1, height))
        resized = self._trace_rt_size != (int(width), int(height))

        for layer in self._trace_layers():
            rt = layer.rt
            if (
                rt is not None
                and int(getattr(rt, "id", 0)) > 0
                and int(getattr(getattr(rt, "texture", None), "width", 0)) == int(width)
                and int(getattr(getattr(rt, "texture", None), "height", 0)) == int(height)
            ):
                continue
            if rt is not None and int(getattr(rt, "id", 0)) > 0:
                rl.unload_render_texture(rt)
            layer.rt = rl.load_render_texture(int(width), int(height))
            rl.begin_texture_mode(layer.rt)
            rl.clear_background(rl.Color(0, 0, 0, 0))
            rl.end_texture_mode()
            resized = True

        if resized:
            self._trace_rt_size = (int(width), int(height))
            # Render target space changed; avoid cross-resolution bridge segments.
            self._trace_prev_capture.clear()
            self._trace_prev_rewrite.clear()

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
        tick = self._session.step_tick(
            dt_frame=float(dt_tick),
            dt_frame_ms_i32=(int(dt_tick_ms_i32) if dt_tick_ms_i32 is not None else None),
            inputs=inputs,
            trace_rng=False,
        )
        rewrite_events = tick.step.events

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
            self._snapshot = self._build_snapshot(
                row,
                rewrite_events=rewrite_events,
                tick_events=tick_events,
            )
            self._append_traces(self._snapshot)

    @staticmethod
    def _timer_map_from_world(world: WorldState) -> dict[str, int]:
        bonuses = world.state.bonuses
        return {
            str(int(BonusId.ENERGIZER)): _bonus_timer_ms(float(bonuses.energizer)),
            str(int(BonusId.WEAPON_POWER_UP)): _bonus_timer_ms(float(bonuses.weapon_power_up)),
            str(int(BonusId.DOUBLE_EXPERIENCE)): _bonus_timer_ms(float(bonuses.double_experience)),
            str(int(BonusId.REFLEX_BOOST)): _bonus_timer_ms(float(bonuses.reflex_boost)),
            str(int(BonusId.FREEZE)): _bonus_timer_ms(float(bonuses.freeze)),
        }

    @staticmethod
    def _timer_summary(timer_map: dict[str, int]) -> str:
        fields = (
            ("ENRG", str(int(BonusId.ENERGIZER))),
            ("WPUP", str(int(BonusId.WEAPON_POWER_UP))),
            ("DXP", str(int(BonusId.DOUBLE_EXPERIENCE))),
            ("RFX", str(int(BonusId.REFLEX_BOOST))),
            ("FRZ", str(int(BonusId.FREEZE))),
        )
        out: list[str] = []
        for label, key in fields:
            out.append(f"{label}={_format_seconds(_int_or(timer_map.get(str(key)), 0))}")
        return " ".join(out)

    @staticmethod
    def _nonzero_perk_counts_from_checkpoint(tick: CaptureTick, *, player_index: int) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        all_players = tick.checkpoint.perk.player_nonzero_counts
        if not (0 <= int(player_index) < len(all_players)):
            return out
        for row in all_players[int(player_index)]:
            if not isinstance(row, list) or len(row) != 2:
                continue
            perk_id = _int_or(row[0], -1)
            count = _int_or(row[1], 0)
            if perk_id < 0 or count <= 0:
                continue
            out.append((int(perk_id), int(count)))
        out.sort(key=lambda item: (-int(item[1]), int(item[0])))
        return out

    @staticmethod
    def _nonzero_perk_counts_from_world(world: WorldState, *, player_index: int) -> list[tuple[int, int]]:
        if not (0 <= int(player_index) < len(world.players)):
            return []
        player = world.players[int(player_index)]
        out: list[tuple[int, int]] = []
        for perk_id, count_raw in enumerate(player.perk_counts):
            count = int(count_raw)
            if count <= 0:
                continue
            out.append((int(perk_id), int(count)))
        out.sort(key=lambda item: (-int(item[1]), int(item[0])))
        return out

    @staticmethod
    def _perk_apply_ids_from_tick(tick: CaptureTick) -> list[int]:
        out: list[int] = []
        seen: set[int] = set()
        for item in tick.perk_apply_in_tick:
            perk_id = _int_or(item.perk_id, -1)
            if perk_id <= 0 or perk_id in seen:
                continue
            seen.add(int(perk_id))
            out.append(int(perk_id))
        return out

    @staticmethod
    def _perk_apply_ids_from_replay_events(events: list[object]) -> list[int]:
        out: list[int] = []
        seen: set[int] = set()
        for event in events:
            if not isinstance(event, UnknownEvent):
                continue
            if str(event.kind) != CAPTURE_PERK_APPLY_EVENT_KIND:
                continue
            perk_id = capture_perk_apply_id_from_event_payload(list(event.payload))
            if perk_id is None or int(perk_id) <= 0 or int(perk_id) in seen:
                continue
            seen.add(int(perk_id))
            out.append(int(perk_id))
        return out

    def _format_perk_choices(self, values: list[int]) -> str:
        if not values:
            return "-"
        labels = [
            _short_text(
                str(
                    perk_label(
                        int(perk_id),
                        preserve_bugs=bool(getattr(self._replay.header, "preserve_bugs", False)),
                    )
                ),
                max_len=18,
            )
            for perk_id in values[:_PERK_PANEL_MAX_CHOICES]
        ]
        return ", ".join(labels)

    def _format_perk_counts(self, values: list[tuple[int, int]]) -> str:
        if not values:
            return "-"
        chunks: list[str] = []
        for perk_id, count in values[:_PERK_PANEL_MAX_COUNTS]:
            name = _short_text(
                str(
                    perk_label(
                        int(perk_id),
                        preserve_bugs=bool(getattr(self._replay.header, "preserve_bugs", False)),
                    )
                ),
                max_len=14,
            )
            count_i = int(count)
            chunks.append(name if count_i == 1 else f"{name}x{count_i}")
        return ", ".join(chunks)

    @staticmethod
    def _weapon_name(weapon_id: int) -> str:
        weapon = WEAPON_BY_ID.get(int(weapon_id))
        if weapon is not None and weapon.name:
            return _short_text(str(weapon.name), max_len=22)
        return f"id{int(weapon_id)}"

    @staticmethod
    def _format_ammo(ammo: float) -> str:
        value = float(_finite(ammo))
        if not math.isfinite(value):
            return "?"
        rounded = int(round(value))
        if math.isclose(value, float(rounded), rel_tol=0.0, abs_tol=1e-6):
            return str(int(rounded))
        return f"{value:.2f}"

    @staticmethod
    def _player_timer_map_from_world(world: WorldState, *, player_index: int = 0) -> dict[str, int]:
        if not (0 <= int(player_index) < len(world.players)):
            return {}
        player = world.players[int(player_index)]
        return {
            "shield": _bonus_timer_ms(float(player.shield_timer)),
            "fire_bullets": _bonus_timer_ms(float(player.fire_bullets_timer)),
            "speed_bonus": _bonus_timer_ms(float(player.speed_bonus_timer)),
        }

    @staticmethod
    def _player_timer_map_from_capture_row(row: CaptureTick, *, player_index: int = 0) -> dict[str, int]:
        if not (0 <= int(player_index) < len(row.checkpoint.players)):
            return {}
        raw = row.checkpoint.players[int(player_index)].bonus_timers
        if not isinstance(raw, dict) or not raw:
            return {}
        out: dict[str, int] = {}
        for key in ("shield", "fire_bullets", "speed_bonus"):
            out[str(key)] = max(0, _int_or(raw.get(str(key)), 0))
        return out

    def _active_bonus_summary(
        self,
        *,
        global_timers: dict[str, int],
        player_timers: dict[str, int],
    ) -> str:
        chunks: list[str] = []

        player_fields = (
            ("Shield", "shield"),
            ("Fire Bullets", "fire_bullets"),
            ("Speed", "speed_bonus"),
        )
        for label, key in player_fields:
            ms = _int_or(player_timers.get(str(key)), 0)
            if int(ms) <= 0:
                continue
            chunks.append(f"{label} {_format_seconds(int(ms))}s")

        ordered_bonus_ids = (
            int(BonusId.ENERGIZER),
            int(BonusId.WEAPON_POWER_UP),
            int(BonusId.DOUBLE_EXPERIENCE),
            int(BonusId.REFLEX_BOOST),
            int(BonusId.FREEZE),
        )
        for bonus_id in ordered_bonus_ids:
            ms = _int_or(global_timers.get(str(int(bonus_id))), 0)
            if int(ms) <= 0:
                continue
            label = _short_text(self._bonus_label_from_entry(BonusEntry(bonus_id=int(bonus_id), amount=0)), max_len=18)
            chunks.append(f"{label} {_format_seconds(int(ms))}s")
        return ", ".join(chunks) if chunks else "-"

    def _build_gameplay_lines(
        self,
        *,
        row: CaptureTick,
        rewrite_events: WorldEvents | None,
        tick_events: list[object],
    ) -> tuple[_GameplayHudLine, ...]:
        assert self._world is not None
        _ = rewrite_events, tick_events

        capture_kills = int(row.checkpoint.kills)
        rewrite_kills = int(self._world.creatures.kill_count)

        capture_p0_xp = int(row.checkpoint.players[0].experience) if row.checkpoint.players else -1
        capture_p0_level = int(row.checkpoint.players[0].level) if row.checkpoint.players else -1
        if self._world.players:
            rewrite_p0_xp = int(self._world.players[0].experience)
            rewrite_p0_level = int(self._world.players[0].level)
        else:
            rewrite_p0_xp = -1
            rewrite_p0_level = -1

        capture_weapon_id = int(row.checkpoint.players[0].weapon_id) if row.checkpoint.players else 0
        capture_ammo = float(row.checkpoint.players[0].ammo) if row.checkpoint.players else 0.0
        if self._world.players:
            rewrite_weapon_id = int(self._world.players[0].weapon_id)
            rewrite_ammo = float(self._world.players[0].ammo)
        else:
            rewrite_weapon_id = 0
            rewrite_ammo = 0.0

        capture_counts = self._nonzero_perk_counts_from_checkpoint(row, player_index=0)
        rewrite_counts = self._nonzero_perk_counts_from_world(self._world, player_index=0)

        capture_global_timers = {str(key): int(value) for key, value in row.checkpoint.bonus_timers.items()}
        rewrite_global_timers = self._timer_map_from_world(self._world)
        capture_player_timers = self._player_timer_map_from_capture_row(row, player_index=0)
        rewrite_player_timers = self._player_timer_map_from_world(self._world, player_index=0)

        lines: list[_GameplayHudLine] = []

        def append_pair(*, left_text: str, right_text: str) -> None:
            lines.append(
                _GameplayHudLine(
                    left_text=left_text,
                    left_color=_CAPTURE_PLAYER_COLOR,
                    right_text=right_text,
                    right_color=_REWRITE_PLAYER_COLOR,
                )
            )

        append_pair(
            left_text=f"xp: {int(capture_p0_xp)} lvl {int(capture_p0_level)}",
            right_text=f"{int(rewrite_p0_xp)} lvl {int(rewrite_p0_level)}",
        )
        append_pair(
            left_text=f"kills: {int(capture_kills)}",
            right_text=f"{int(rewrite_kills)}",
        )
        append_pair(
            left_text=f"weapon: {self._weapon_name(capture_weapon_id)} ammo {self._format_ammo(capture_ammo)}",
            right_text=f"{self._weapon_name(rewrite_weapon_id)} ammo {self._format_ammo(rewrite_ammo)}",
        )
        lines.append(_GameplayHudLine(left_text="", left_color=_TEXT_DIM_COLOR))

        lines.append(
            _GameplayHudLine(
                left_text="perks:",
                left_color=_TEXT_DIM_COLOR,
            )
        )
        lines.append(
            _GameplayHudLine(
                left_text=self._format_perk_counts(capture_counts),
                left_color=_CAPTURE_PLAYER_COLOR,
            )
        )
        lines.append(
            _GameplayHudLine(
                left_text=self._format_perk_counts(rewrite_counts),
                left_color=_REWRITE_PLAYER_COLOR,
            )
        )

        capture_bonus_active = self._active_bonus_summary(
            global_timers=capture_global_timers,
            player_timers=capture_player_timers,
        )
        rewrite_bonus_active = self._active_bonus_summary(
            global_timers=rewrite_global_timers,
            player_timers=rewrite_player_timers,
        )
        has_active_bonuses = capture_bonus_active != "-" or rewrite_bonus_active != "-"
        if has_active_bonuses:
            lines.append(_GameplayHudLine(left_text="", left_color=_TEXT_DIM_COLOR))
            lines.append(
                _GameplayHudLine(
                    left_text="bonuses:",
                    left_color=_TEXT_DIM_COLOR,
                )
            )
            lines.append(
                _GameplayHudLine(
                    left_text=capture_bonus_active,
                    left_color=_CAPTURE_PLAYER_COLOR,
                )
            )
            lines.append(
                _GameplayHudLine(
                    left_text=rewrite_bonus_active,
                    left_color=_REWRITE_PLAYER_COLOR,
                )
            )
        return tuple(lines)

    def _build_snapshot(
        self,
        row: CaptureTick,
        *,
        rewrite_events: WorldEvents | None,
        tick_events: list[object],
    ) -> _FrameSnapshot:
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
        capture_bonuses: dict[int, _BonusDraw] = {}
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
            if self._capture_secondary_world_space:
                for sample in samples.secondary_projectiles:
                    capture_secondary[int(sample.index)] = _EntityDraw(
                        x=_finite(sample.pos.x),
                        y=_finite(sample.pos.y),
                        radius=3.5,
                        active=bool(int(sample.active) != 0),
                    )
            for sample in samples.bonuses:
                bonus_id = int(sample.bonus_id)
                state = int(sample.state)
                active = bool(bonus_id > 0 and state >= 0)
                if not active:
                    continue
                capture_bonuses[int(sample.index)] = _BonusDraw(
                    x=_finite(sample.pos.x),
                    y=_finite(sample.pos.y),
                    label=self._bonus_label_from_capture_sample(
                        bonus_id=int(bonus_id),
                        amount_i32=int(sample.amount_i32),
                    ),
                    active=True,
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

        rewrite_bonuses: dict[int, _BonusDraw] = {}
        for idx, entry in enumerate(self._world.state.bonus_pool.entries):
            bonus_id = int(entry.bonus_id)
            if bonus_id <= 0:
                continue
            rewrite_bonuses[int(idx)] = _BonusDraw(
                x=_finite(entry.pos.x),
                y=_finite(entry.pos.y),
                label=self._bonus_label_from_entry(entry),
                active=True,
            )

        sample_counts = {
            "creatures": int(len(capture_creatures)),
            "projectiles": int(len(capture_projectiles)),
            "secondary_projectiles": int(len(capture_secondary)),
            "bonuses": int(len(capture_bonuses)),
        }
        gameplay_lines = self._build_gameplay_lines(
            row=row,
            rewrite_events=rewrite_events,
            tick_events=tick_events,
        )
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
            capture_bonuses=capture_bonuses,
            rewrite_bonuses=rewrite_bonuses,
            capture_sample_counts=sample_counts,
            gameplay_lines=gameplay_lines,
        )

    def _bonus_label_from_entry(self, entry: BonusEntry) -> str:
        try:
            return str(
                bonus_label_for_entry(
                    entry,
                    preserve_bugs=bool(getattr(self._replay.header, "preserve_bugs", False)),
                )
            )
        except Exception:
            return "Bonus"

    def _bonus_label_from_capture_sample(self, *, bonus_id: int, amount_i32: int) -> str:
        return self._bonus_label_from_entry(
            BonusEntry(
                bonus_id=int(bonus_id),
                amount=int(amount_i32),
            )
        )

    def _trace_layer_for_key(self, key: str) -> _TraceLayer:
        if key.startswith("p:"):
            return self._player_traces
        if key.startswith("c:"):
            return self._creature_traces
        # Both projectile pools (primary + secondary) use the projectile layer.
        return self._projectile_traces

    @staticmethod
    def _is_projectile_trace_key(key: str) -> bool:
        return key.startswith("pr:") or key.startswith("spr:")

    @staticmethod
    def _dist_sq(x0: float, y0: float, x1: float, y1: float) -> float:
        dx = float(x1) - float(x0)
        dy = float(y1) - float(y0)
        return float(dx * dx + dy * dy)

    @staticmethod
    def _apply_linear_subtract_fade(rt: rl.RenderTexture, *, amount: int) -> None:
        amount = int(max(0, min(255, int(amount))))
        if amount <= 0:
            return
        width = int(max(1, getattr(rt.texture, "width", 1)))
        height = int(max(1, getattr(rt.texture, "height", 1)))
        fade_color = rl.Color(int(amount), int(amount), int(amount), int(amount))
        rl.begin_texture_mode(rt)
        rl.rl_set_blend_factors_separate(
            rd.RL_ONE,
            rd.RL_ONE,
            rd.RL_ONE,
            rd.RL_ONE,
            rd.RL_FUNC_REVERSE_SUBTRACT,
            rd.RL_FUNC_REVERSE_SUBTRACT,
        )
        rl.begin_blend_mode(rl.BlendMode.BLEND_CUSTOM_SEPARATE)
        rl.rl_set_blend_factors_separate(
            rd.RL_ONE,
            rd.RL_ONE,
            rd.RL_ONE,
            rd.RL_ONE,
            rd.RL_FUNC_REVERSE_SUBTRACT,
            rd.RL_FUNC_REVERSE_SUBTRACT,
        )
        rl.draw_rectangle(0, 0, int(width), int(height), fade_color)
        rl.end_blend_mode()
        rl.end_texture_mode()

    def _fade_trace_layers(self, *, sim_dt: float) -> None:
        if sim_dt <= 0.0:
            return
        for layer in self._trace_layers():
            rt = layer.rt
            if rt is None or int(getattr(rt, "id", 0)) <= 0:
                continue
            duration = max(float(self._step_interval), float(layer.lifetime_ticks) * float(self._step_interval))
            # Linear decay over the configured trail lifetime.
            # Keep sub-byte precision in `fade_accum` so long lifetimes (e.g. player=1200)
            # still decay every frame.
            layer.fade_accum += (max(0.0, float(sim_dt)) * 255.0) / float(duration)
            fade_amount = int(layer.fade_accum)
            if fade_amount <= 0:
                continue
            layer.fade_accum -= float(fade_amount)
            self._apply_linear_subtract_fade(rt, amount=int(fade_amount))

    def _draw_trace_layers(self, *, width: int, height: int) -> None:
        dst = rl.Rectangle(0.0, 0.0, float(width), float(height))
        # Draw in this order so player trails remain easiest to read.
        for layer in (self._creature_traces, self._projectile_traces, self._player_traces):
            rt = layer.rt
            if rt is None or int(getattr(rt, "id", 0)) <= 0:
                continue
            src = rl.Rectangle(
                0.0,
                0.0,
                float(getattr(rt.texture, "width", width)),
                -float(getattr(rt.texture, "height", height)),
            )
            rl.draw_texture_pro(rt.texture, src, dst, rl.Vector2(0.0, 0.0), 0.0, rl.WHITE)

    def _trace_thickness_for_layer(self, layer: _TraceLayer) -> float:
        if layer is self._player_traces:
            return 3.0
        return 1.0

    def _stamp_trace_segment(
        self,
        *,
        layer: _TraceLayer,
        x0: float,
        y0: float,
        x1: float,
        y1: float,
        width: int,
        height: int,
        color: rl.Color,
    ) -> None:
        rt = layer.rt
        if rt is None or int(getattr(rt, "id", 0)) <= 0:
            return
        sx0, sy0 = self._world_to_screen(x=float(x0), y=float(y0), width=width, height=height)
        sx1, sy1 = self._world_to_screen(x=float(x1), y=float(y1), width=width, height=height)
        rl.begin_texture_mode(rt)
        rl.draw_line_ex(
            rl.Vector2(float(sx0), float(sy0)),
            rl.Vector2(float(sx1), float(sy1)),
            float(self._trace_thickness_for_layer(layer)),
            color,
        )
        rl.end_texture_mode()

    def _append_trace_point(
        self,
        key: str,
        *,
        tick_index: int,
        capture: _EntityDraw | None,
        rewrite: _EntityDraw | None,
        width: int,
        height: int,
    ) -> None:
        layer = self._trace_layer_for_key(key)
        projectile_key = bool(self._is_projectile_trace_key(key))

        capture_active = capture is not None and bool(capture.active)
        if capture_active and capture is not None:
            cx = float(capture.x)
            cy = float(capture.y)
            prev = self._trace_prev_capture.get(key)
            if prev is not None:
                prev_tick, px, py = prev
                if int(tick_index) - int(prev_tick) == 1:
                    if (not projectile_key) or (
                        self._dist_sq(float(px), float(py), float(cx), float(cy))
                        <= float(_PROJECTILE_TRACE_RESET_DIST * _PROJECTILE_TRACE_RESET_DIST)
                    ):
                        self._stamp_trace_segment(
                            layer=layer,
                            x0=float(px),
                            y0=float(py),
                            x1=float(cx),
                            y1=float(cy),
                            width=width,
                            height=height,
                            color=_CAPTURE_TRACE_COLOR,
                        )
            self._trace_prev_capture[key] = (int(tick_index), float(cx), float(cy))
        else:
            self._trace_prev_capture.pop(key, None)

        rewrite_active = rewrite is not None and bool(rewrite.active)
        if rewrite_active and rewrite is not None:
            rx = float(rewrite.x)
            ry = float(rewrite.y)
            prev = self._trace_prev_rewrite.get(key)
            if prev is not None:
                prev_tick, px, py = prev
                if int(tick_index) - int(prev_tick) == 1:
                    if (not projectile_key) or (
                        self._dist_sq(float(px), float(py), float(rx), float(ry))
                        <= float(_PROJECTILE_TRACE_RESET_DIST * _PROJECTILE_TRACE_RESET_DIST)
                    ):
                        self._stamp_trace_segment(
                            layer=layer,
                            x0=float(px),
                            y0=float(py),
                            x1=float(rx),
                            y1=float(ry),
                            width=width,
                            height=height,
                            color=_REWRITE_TRACE_COLOR,
                        )
            self._trace_prev_rewrite[key] = (int(tick_index), float(rx), float(ry))
        else:
            self._trace_prev_rewrite.pop(key, None)

    def _append_traces(self, snapshot: _FrameSnapshot) -> None:
        tick_index = int(snapshot.tick_index)
        width = int(rl.get_screen_width())
        height = int(rl.get_screen_height())
        if width > 0 and height > 0:
            self._ensure_trace_layers(width=width, height=height)

        capture_keys_seen: set[str] = set()
        rewrite_keys_seen: set[str] = set()

        for idx in sorted(set(snapshot.capture_players) | set(snapshot.rewrite_players)):
            key = f"p:{int(idx)}"
            capture = snapshot.capture_players.get(int(idx))
            rewrite = snapshot.rewrite_players.get(int(idx))
            if capture is not None and bool(capture.active):
                capture_keys_seen.add(str(key))
            if rewrite is not None and bool(rewrite.active):
                rewrite_keys_seen.add(str(key))
            self._append_trace_point(
                key,
                tick_index=int(tick_index),
                capture=capture,
                rewrite=rewrite,
                width=width,
                height=height,
            )
        for idx in sorted(set(snapshot.capture_creatures) | set(snapshot.rewrite_creatures)):
            key = f"c:{int(idx)}"
            capture = snapshot.capture_creatures.get(int(idx))
            rewrite = snapshot.rewrite_creatures.get(int(idx))
            if capture is not None and bool(capture.active):
                capture_keys_seen.add(str(key))
            if rewrite is not None and bool(rewrite.active):
                rewrite_keys_seen.add(str(key))
            self._append_trace_point(
                key,
                tick_index=int(tick_index),
                capture=capture,
                rewrite=rewrite,
                width=width,
                height=height,
            )
        for idx in sorted(set(snapshot.capture_projectiles) | set(snapshot.rewrite_projectiles)):
            key = f"pr:{int(idx)}"
            capture = snapshot.capture_projectiles.get(int(idx))
            rewrite = snapshot.rewrite_projectiles.get(int(idx))
            if capture is not None and bool(capture.active):
                capture_keys_seen.add(str(key))
            if rewrite is not None and bool(rewrite.active):
                rewrite_keys_seen.add(str(key))
            self._append_trace_point(
                key,
                tick_index=int(tick_index),
                capture=capture,
                rewrite=rewrite,
                width=width,
                height=height,
            )
        for idx in sorted(set(snapshot.capture_secondary) | set(snapshot.rewrite_secondary)):
            key = f"spr:{int(idx)}"
            capture = snapshot.capture_secondary.get(int(idx))
            rewrite = snapshot.rewrite_secondary.get(int(idx))
            if capture is not None and bool(capture.active):
                capture_keys_seen.add(str(key))
            if rewrite is not None and bool(rewrite.active):
                rewrite_keys_seen.add(str(key))
            self._append_trace_point(
                key,
                tick_index=int(tick_index),
                capture=capture,
                rewrite=rewrite,
                width=width,
                height=height,
            )

        for key in list(self._trace_prev_capture):
            if str(key) not in capture_keys_seen:
                self._trace_prev_capture.pop(str(key), None)
        for key in list(self._trace_prev_rewrite):
            if str(key) not in rewrite_keys_seen:
                self._trace_prev_rewrite.pop(str(key), None)

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
        if rl.is_key_pressed(rl.KeyboardKey.KEY_H):
            self._show_help = not bool(self._show_help)
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
        sim_dt = max(0.0, float(dt)) * float(self._playback_speed)
        self._trace_fade_dt = 0.0
        if self._paused:
            return
        if self._row_cursor >= self._visible_end_idx:
            return
        if self._step_interval <= 0.0:
            self._step_interval = 1.0 / 60.0
        self._trace_fade_dt = float(sim_dt)
        self._accumulator += float(sim_dt)
        while self._row_cursor < self._visible_end_idx:
            next_idx = int(self._row_cursor) + 1
            if next_idx < self._visible_start_idx:
                next_idx = int(self._visible_start_idx)
            if next_idx > self._visible_end_idx:
                break
            next_row = self._rows[int(next_idx)]
            tick_interval = _resolve_dt_frame(
                tick_index=int(next_row.tick_index),
                default_dt_frame=float(self._step_interval),
                dt_frame_overrides=self._dt_frame_overrides,
            )
            if float(tick_interval) <= 0.0:
                tick_interval = float(self._step_interval)
            tick_advance = float(tick_interval)
            if tick_advance <= 0.0:
                tick_advance = float(self._step_interval)
            if self._accumulator < float(tick_advance):
                break
            self._accumulator -= float(tick_advance)
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

    def _draw_bonus_overlay(
        self,
        *,
        capture_map: dict[int, _BonusDraw],
        rewrite_map: dict[int, _BonusDraw],
        width: int,
        height: int,
    ) -> None:
        bonus_radius = self._radius_to_screen(float(_BONUS_DRAW_RADIUS), width=width, height=height)
        for key in sorted(set(capture_map) | set(rewrite_map)):
            capture = capture_map.get(int(key))
            rewrite = rewrite_map.get(int(key))
            if self._show_capture_hitboxes and capture is not None and bool(capture.active):
                cx, cy = self._world_to_screen(
                    x=float(capture.x),
                    y=float(capture.y),
                    width=width,
                    height=height,
                )
                rl.draw_circle_lines(int(cx), int(cy), float(bonus_radius), _CAPTURE_BONUS_COLOR)
                self._draw_ui_text(
                    str(capture.label),
                    x=float(cx) + float(bonus_radius) + 4.0,
                    y=float(cy) - 10.0,
                    color=_CAPTURE_BONUS_COLOR,
                    scale=0.8,
                )
            if self._show_rewrite_hitboxes and rewrite is not None and bool(rewrite.active):
                rx, ry = self._world_to_screen(
                    x=float(rewrite.x),
                    y=float(rewrite.y),
                    width=width,
                    height=height,
                )
                rl.draw_circle_lines(int(rx), int(ry), float(bonus_radius), _REWRITE_BONUS_COLOR)
                self._draw_ui_text(
                    str(rewrite.label),
                    x=float(rx) + float(bonus_radius) + 4.0,
                    y=float(ry) + 2.0,
                    color=_REWRITE_BONUS_COLOR,
                    scale=0.8,
                )

    def _draw_ui_text(self, text: str, *, x: float, y: float, color: rl.Color, scale: float = 1.0) -> None:
        if self._small is not None:
            draw_small_text(self._small, text, Vec2(float(x), float(y)), float(scale), color)
            return
        rl.draw_text(text, int(x), int(y), int(20 * float(scale)), color)

    def _ui_text_width(self, text: str, *, scale: float = 1.0) -> float:
        if self._small is not None:
            return float(measure_small_text_width(self._small, str(text), float(scale)))
        return float(rl.measure_text(str(text), int(20 * float(scale))))

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

        self._ensure_trace_layers(width=width, height=height)
        self._fade_trace_layers(sim_dt=float(self._trace_fade_dt))
        if self._show_traces:
            self._draw_trace_layers(width=width, height=height)

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
        self._draw_bonus_overlay(
            capture_map=snapshot.capture_bonuses,
            rewrite_map=snapshot.rewrite_bonuses,
            width=width,
            height=height,
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
            (
                f"samples: creatures={snapshot.capture_sample_counts['creatures']}  "
                f"projectiles={snapshot.capture_sample_counts['projectiles']}  "
                f"secondary={snapshot.capture_sample_counts['secondary_projectiles']}  "
                f"bonuses={snapshot.capture_sample_counts['bonuses']}"
            ),
            x=16.0,
            y=34.0,
            color=_TEXT_DIM_COLOR,
            scale=1.0,
        )
        gameplay_y = 52.0
        for line in snapshot.gameplay_lines:
            if line.left_text:
                self._draw_ui_text(
                    line.left_text,
                    x=16.0,
                    y=float(gameplay_y),
                    color=line.left_color,
                    scale=1.0,
                )
            if line.right_text:
                right_x = 16.0
                if line.left_text:
                    right_x = 16.0 + self._ui_text_width(f"{line.left_text}  ", scale=1.0)
                self._draw_ui_text(
                    line.right_text,
                    x=float(right_x),
                    y=float(gameplay_y),
                    color=line.right_color or _TEXT_DIM_COLOR,
                    scale=1.0,
                )
            gameplay_y += 18.0
        if self._show_help:
            self._draw_ui_text(
                "capture trace (cyan) vs rewrite trace (orange), hitbox-only overlay",
                x=16.0,
                y=float(gameplay_y),
                color=_TEXT_DIM_COLOR,
                scale=1.0,
            )
            gameplay_y += 18.0
            self._draw_ui_text(
                (
                    "Space pause  Right step  R restart  [ slower ] faster  "
                    "T traces  L divergence-lines  C capture-hitboxes  V rewrite-hitboxes  H help  Esc close"
                ),
                x=16.0,
                y=float(gameplay_y),
                color=_TEXT_DIM_COLOR,
                scale=1.0,
            )
            gameplay_y += 18.0
        else:
            self._draw_ui_text("H help", x=16.0, y=float(gameplay_y), color=_TEXT_DIM_COLOR, scale=1.0)
            gameplay_y += 18.0
        if not self._capture_secondary_world_space:
            self._draw_ui_text(
                "note: capture secondary samples look non-world-space; capture secondary overlay disabled",
                x=16.0,
                y=float(gameplay_y),
                color=_TEXT_DIM_COLOR,
                scale=1.0,
            )
            gameplay_y += 18.0

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
    parser.add_argument(
        "--aim-scheme-player",
        action="append",
        default=[],
        metavar="PLAYER=SCHEME",
        help=(
            "override replay reconstruction aim scheme as PLAYER=SCHEME (repeatable); "
            "use for captures missing config_aim_scheme telemetry"
        ),
    )
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
    try:
        aim_scheme_overrides = parse_player_int_overrides(
            args.aim_scheme_player,
            option_name="--aim-scheme-player",
        )
    except ValueError as exc:
        print(str(exc))
        return 2

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
            aim_scheme_overrides_by_player=aim_scheme_overrides,
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
