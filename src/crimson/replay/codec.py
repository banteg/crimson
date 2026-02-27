from __future__ import annotations

import gzip
import io
import os
from pathlib import Path
from typing import TypeAlias

import msgspec

from ..math_parity import f32
from .types import (
    CAPTURE_BOOTSTRAP_EVENT_KIND,
    CAPTURE_CREATURE_SPAWN_EVENT_KIND,
    CAPTURE_PERK_APPLY_EVENT_KIND,
    CAPTURE_PERK_PENDING_EVENT_KIND,
    CAPTURE_STATE_TRANSITION_EVENT_KIND,
    REPLAY_FORMAT_VERSION,
    WEAPON_USAGE_COUNT,
    BootstrapKind,
    CaptureBootstrapEvent,
    CaptureBootstrapPlayer,
    CaptureBootstrapQuestSession,
    CaptureCreatureSpawnAddedHeadRow,
    CaptureCreatureSpawnEvent,
    CaptureCreatureSpawnRow,
    CapturePerkApplyEvent,
    CapturePerkPendingEvent,
    CaptureStateTransitionEvent,
    CaptureStateTransitionRow,
    InputQuantization,
    PackedPlayerInput,
    PackedTickInputs,
    PerkMenuOpenEvent,
    PerkPickEvent,
    Replay,
    ReplayClaimedStatsSnapshot,
    ReplayEvent,
    ReplayHeader,
    ReplayStatusSnapshot,
)

_GZIP_MAGIC = b"\x1f\x8b"
_DEFAULT_MAX_REPLAY_PAYLOAD_BYTES = 64 * 1024 * 1024
_MAX_REPLAY_PAYLOAD_ENV = "CRIMSON_REPLAY_MAX_DECOMPRESSED_BYTES"


class ReplayCodecError(ValueError):
    pass


class _ReplayStatusWire(msgspec.Struct, forbid_unknown_fields=True):
    quest_unlock_index: int = 0
    quest_unlock_index_full: int = 0
    weapon_usage_counts: list[int] = msgspec.field(default_factory=list)


class _ReplayClaimedStatsWire(msgspec.Struct, forbid_unknown_fields=True):
    complete: bool = False
    ticks: int = 0
    elapsed_ms: int = 0
    score_xp: int = 0
    kills: int = 0
    most_used_weapon_id: int = 0
    shots_fired: int = 0
    shots_hit: int = 0


class _ReplayHeaderWire(msgspec.Struct, forbid_unknown_fields=True):
    game_mode_id: int
    seed: int
    replay_format_version: int
    claimed_stats: _ReplayClaimedStatsWire
    quest_level: str = ""
    bootstrap_kind: str = "none"
    bootstrap_seed: int = 0
    game_version: str = ""
    tick_rate: int = 60
    difficulty_level: int = 0
    hardcore: bool = False
    preserve_bugs: bool = False
    detail_preset: int = 5
    fx_toggle: int = 0
    world_size: float = 1024.0
    player_count: int = 1
    status: _ReplayStatusWire = msgspec.field(default_factory=_ReplayStatusWire)
    input_quantization: str = "f32"


class _ReplayInputWire(msgspec.Struct, array_like=True, forbid_unknown_fields=True):
    move_x: float
    move_y: float
    aim_x: float
    aim_y: float
    flags: int


class _PerkPickEventWire(msgspec.Struct, tag="perk_pick", tag_field="kind", forbid_unknown_fields=True):
    tick_index: int
    player_index: int
    choice_index: int


class _PerkMenuOpenEventWire(msgspec.Struct, tag="perk_menu_open", tag_field="kind", forbid_unknown_fields=True):
    tick_index: int
    player_index: int


class _CaptureBootstrapQuestSessionWire(msgspec.Struct, forbid_unknown_fields=True):
    spawn_timeline_ms: float | None
    no_creatures_timer_ms: float | None
    completion_transition_ms: float | None


class _CaptureBootstrapPlayerWire(msgspec.Struct, forbid_unknown_fields=True):
    weapon_id: int
    pos_x: float
    pos_y: float
    health: float
    ammo: float
    experience: int
    level: int
    clip_size: int | None
    reload_active: bool | None
    reload_timer: float | None
    reload_timer_max: float | None
    shot_cooldown: float | None
    spread_heat: float | None
    aim_x: float | None
    aim_y: float | None
    aim_heading: float | None
    alt_weapon_id: int | None
    alt_clip_size: int | None
    alt_ammo: float | None
    alt_reload_active: bool | None
    alt_reload_timer: float | None
    alt_reload_timer_max: float | None
    alt_shot_cooldown: float | None
    shield_ms: int | None
    fire_bullets_ms: int | None
    speed_bonus_ms: int | None
    hot_tempered_timer: float | None
    man_bomb_timer: float | None
    living_fortress_timer: float | None
    fire_cough_timer: float | None


class _CaptureBootstrapEventWire(
    msgspec.Struct,
    tag=CAPTURE_BOOTSTRAP_EVENT_KIND,
    tag_field="kind",
    forbid_unknown_fields=True,
):
    tick_index: int
    elapsed_ms: int
    score_xp: int
    perk_pending: int
    perk_pending_count: int
    perk_choices_dirty: bool
    perk_choices: list[int]
    player_nonzero_counts: list[list[list[int]]]
    players: list[_CaptureBootstrapPlayerWire]
    digital_move_enabled_by_player: list[bool]
    weapon_power_up_ms: int
    reflex_boost_ms: int
    energizer_ms: int
    double_experience_ms: int
    freeze_ms: int
    perk_interval_man_bomb: float | None
    perk_interval_fire_cough: float | None
    perk_interval_hot_tempered: float | None
    quest_session: _CaptureBootstrapQuestSessionWire | None


class _CapturePerkApplyEventWire(
    msgspec.Struct,
    tag=CAPTURE_PERK_APPLY_EVENT_KIND,
    tag_field="kind",
    forbid_unknown_fields=True,
):
    tick_index: int
    perk_id: int
    outside_before: bool
    pending_before: int | None
    pending_after: int | None


class _CapturePerkPendingEventWire(
    msgspec.Struct,
    tag=CAPTURE_PERK_PENDING_EVENT_KIND,
    tag_field="kind",
    forbid_unknown_fields=True,
):
    tick_index: int
    perk_pending: int


class _CaptureCreatureSpawnRowWire(msgspec.Struct, forbid_unknown_fields=True):
    template_id: int
    pos_x: float
    pos_y: float
    heading: float


class _CaptureCreatureSpawnAddedHeadRowWire(msgspec.Struct, forbid_unknown_fields=True):
    index: int
    heading: float | None
    target_heading: float | None
    ai_mode: int | None
    link_index: int | None
    hp: float | None
    lifecycle_stage: float | None
    orbit_angle: float | None
    orbit_radius: float | None
    flags: int | None
    type_id: int | None
    pos_x: float | None
    pos_y: float | None


class _CaptureCreatureSpawnEventWire(
    msgspec.Struct,
    tag=CAPTURE_CREATURE_SPAWN_EVENT_KIND,
    tag_field="kind",
    forbid_unknown_fields=True,
):
    tick_index: int
    spawns: list[_CaptureCreatureSpawnRowWire]
    added_head: list[_CaptureCreatureSpawnAddedHeadRowWire]


class _CaptureStateTransitionRowWire(msgspec.Struct, forbid_unknown_fields=True):
    target_state: int
    before_state: int | None
    after_state: int | None


class _CaptureStateTransitionEventWire(
    msgspec.Struct,
    tag=CAPTURE_STATE_TRANSITION_EVENT_KIND,
    tag_field="kind",
    forbid_unknown_fields=True,
):
    tick_index: int
    transitions: list[_CaptureStateTransitionRowWire]


_ReplayEventWire: TypeAlias = (
    _PerkPickEventWire
    | _PerkMenuOpenEventWire
    | _CaptureBootstrapEventWire
    | _CapturePerkApplyEventWire
    | _CapturePerkPendingEventWire
    | _CaptureCreatureSpawnEventWire
    | _CaptureStateTransitionEventWire
)


class _ReplayWire(msgspec.Struct, forbid_unknown_fields=True):
    header: _ReplayHeaderWire
    inputs: list[list[_ReplayInputWire]]
    events: list[_ReplayEventWire] = msgspec.field(default_factory=list)


_REPLAY_DECODER = msgspec.msgpack.Decoder(type=_ReplayWire)


def _is_gzip(data: bytes) -> bool:
    return data.startswith(_GZIP_MAGIC)


def _max_replay_payload_bytes() -> int:
    raw = os.environ.get(_MAX_REPLAY_PAYLOAD_ENV)
    if raw is None:
        return int(_DEFAULT_MAX_REPLAY_PAYLOAD_BYTES)
    try:
        parsed = int(raw)
    except ValueError:
        return int(_DEFAULT_MAX_REPLAY_PAYLOAD_BYTES)
    if parsed <= 0:
        return int(_DEFAULT_MAX_REPLAY_PAYLOAD_BYTES)
    return int(parsed)


def _decompress_gzip_replay(data: bytes, *, max_output_bytes: int) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
            payload = stream.read(int(max_output_bytes) + 1)
    except OSError as exc:
        raise ReplayCodecError("invalid replay gzip payload") from exc
    if len(payload) > int(max_output_bytes):
        raise ReplayCodecError(
            f"replay payload too large after gzip decompression (> {int(max_output_bytes)} bytes)",
        )
    return payload


def _quantize_f32(value: float) -> float:
    # Canonicalize via shared math-parity float32 helper.
    return float(f32(float(value)))


def _validate_usage_counts(counts: tuple[int, ...] | list[int]) -> None:
    if len(counts) != int(WEAPON_USAGE_COUNT):
        raise ReplayCodecError(
            f"replay header status.weapon_usage_counts must have {int(WEAPON_USAGE_COUNT)} entries",
        )


def _validate_claimed_stats(stats: ReplayClaimedStatsSnapshot) -> None:
    if int(stats.ticks) < 0:
        raise ReplayCodecError(f"replay header claimed_stats.ticks must be non-negative, got {int(stats.ticks)}")
    if int(stats.elapsed_ms) < 0:
        raise ReplayCodecError(
            f"replay header claimed_stats.elapsed_ms must be non-negative, got {int(stats.elapsed_ms)}",
        )
    if int(stats.score_xp) < 0:
        raise ReplayCodecError(
            f"replay header claimed_stats.score_xp must be non-negative, got {int(stats.score_xp)}",
        )
    if int(stats.kills) < 0:
        raise ReplayCodecError(f"replay header claimed_stats.kills must be non-negative, got {int(stats.kills)}")
    if int(stats.shots_fired) < 0:
        raise ReplayCodecError(
            f"replay header claimed_stats.shots_fired must be non-negative, got {int(stats.shots_fired)}",
        )
    if int(stats.shots_hit) < 0:
        raise ReplayCodecError(
            f"replay header claimed_stats.shots_hit must be non-negative, got {int(stats.shots_hit)}",
        )
    if int(stats.shots_hit) > int(stats.shots_fired):
        raise ReplayCodecError(
            "replay header claimed_stats.shots_hit must be <= claimed_stats.shots_fired",
        )


def _header_to_wire(header: ReplayHeader) -> _ReplayHeaderWire:
    if int(header.replay_format_version) != int(REPLAY_FORMAT_VERSION):
        raise ReplayCodecError(
            f"unsupported replay format version in header: {int(header.replay_format_version)}",
        )
    if int(header.player_count) <= 0:
        raise ReplayCodecError(f"replay header player_count must be positive, got {int(header.player_count)}")
    _validate_usage_counts(header.status.weapon_usage_counts)
    if str(header.input_quantization) != "f32":
        raise ReplayCodecError(f"unsupported input_quantization: {header.input_quantization!r}; expected 'f32'")
    if str(header.bootstrap_kind) not in ("none", "terrain_v1"):
        raise ReplayCodecError(f"unknown bootstrap_kind: {header.bootstrap_kind!r}")
    _validate_claimed_stats(header.claimed_stats)
    claimed_stats_wire = _ReplayClaimedStatsWire(
        complete=bool(header.claimed_stats.complete),
        ticks=int(header.claimed_stats.ticks),
        elapsed_ms=int(header.claimed_stats.elapsed_ms),
        score_xp=int(header.claimed_stats.score_xp),
        kills=int(header.claimed_stats.kills),
        most_used_weapon_id=int(header.claimed_stats.most_used_weapon_id),
        shots_fired=int(header.claimed_stats.shots_fired),
        shots_hit=int(header.claimed_stats.shots_hit),
    )

    return _ReplayHeaderWire(
        game_mode_id=int(header.game_mode_id),
        seed=int(header.seed),
        replay_format_version=int(header.replay_format_version),
        quest_level=str(header.quest_level),
        bootstrap_kind=str(header.bootstrap_kind),
        bootstrap_seed=int(header.bootstrap_seed),
        game_version=str(header.game_version),
        tick_rate=int(header.tick_rate),
        difficulty_level=int(header.difficulty_level),
        hardcore=bool(header.hardcore),
        preserve_bugs=bool(header.preserve_bugs),
        detail_preset=int(header.detail_preset),
        fx_toggle=int(header.fx_toggle),
        world_size=float(header.world_size),
        player_count=int(header.player_count),
        status=_ReplayStatusWire(
            quest_unlock_index=int(header.status.quest_unlock_index),
            quest_unlock_index_full=int(header.status.quest_unlock_index_full),
            weapon_usage_counts=[int(value) for value in header.status.weapon_usage_counts],
        ),
        claimed_stats=claimed_stats_wire,
        input_quantization=str(header.input_quantization),
    )


def _header_from_wire(data: _ReplayHeaderWire) -> ReplayHeader:
    if int(data.replay_format_version) != int(REPLAY_FORMAT_VERSION):
        raise ReplayCodecError(f"unsupported replay format version: {int(data.replay_format_version)}")
    if int(data.player_count) <= 0:
        raise ReplayCodecError(f"replay header player_count must be positive, got {int(data.player_count)}")

    input_quant_raw = str(data.input_quantization)
    if input_quant_raw != "f32":
        raise ReplayCodecError(f"unsupported input_quantization: {input_quant_raw!r}; expected 'f32'")
    input_quant: InputQuantization = "f32"

    bootstrap_kind_raw = str(data.bootstrap_kind)
    if bootstrap_kind_raw not in ("none", "terrain_v1"):
        raise ReplayCodecError(f"unknown bootstrap_kind: {bootstrap_kind_raw!r}")
    bootstrap_kind: BootstrapKind = "terrain_v1" if bootstrap_kind_raw == "terrain_v1" else "none"

    weapon_usage_counts = tuple(int(value) for value in data.status.weapon_usage_counts)
    _validate_usage_counts(weapon_usage_counts)
    status = ReplayStatusSnapshot(
        quest_unlock_index=int(data.status.quest_unlock_index),
        quest_unlock_index_full=int(data.status.quest_unlock_index_full),
        weapon_usage_counts=weapon_usage_counts,
    )
    claimed_stats = ReplayClaimedStatsSnapshot(
        complete=bool(data.claimed_stats.complete),
        ticks=int(data.claimed_stats.ticks),
        elapsed_ms=int(data.claimed_stats.elapsed_ms),
        score_xp=int(data.claimed_stats.score_xp),
        kills=int(data.claimed_stats.kills),
        most_used_weapon_id=int(data.claimed_stats.most_used_weapon_id),
        shots_fired=int(data.claimed_stats.shots_fired),
        shots_hit=int(data.claimed_stats.shots_hit),
    )
    _validate_claimed_stats(claimed_stats)

    return ReplayHeader(
        game_mode_id=int(data.game_mode_id),
        seed=int(data.seed),
        replay_format_version=int(data.replay_format_version),
        quest_level=str(data.quest_level),
        bootstrap_kind=bootstrap_kind,
        bootstrap_seed=int(data.bootstrap_seed),
        game_version=str(data.game_version),
        tick_rate=int(data.tick_rate),
        difficulty_level=int(data.difficulty_level),
        hardcore=bool(data.hardcore),
        preserve_bugs=bool(data.preserve_bugs),
        detail_preset=int(data.detail_preset),
        fx_toggle=int(data.fx_toggle),
        world_size=float(data.world_size),
        player_count=int(data.player_count),
        status=status,
        claimed_stats=claimed_stats,
        input_quantization=input_quant,
    )


def _packed_input_to_wire(
    packed: PackedPlayerInput,
    *,
    tick_idx: int,
    player_idx: int,
) -> _ReplayInputWire:
    if len(packed) != 5:
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} must have 5 fields")
    move_x_raw, move_y_raw, aim_x_raw, aim_y_raw, flags_raw = packed
    if not isinstance(move_x_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} move_x must be numeric")
    if not isinstance(move_y_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} move_y must be numeric")
    if not isinstance(aim_x_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} aim_x must be numeric")
    if not isinstance(aim_y_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} aim_y must be numeric")
    if not isinstance(flags_raw, (int, float)):
        raise ReplayCodecError(f"replay input tick {tick_idx} player {player_idx} flags must be numeric")
    return _ReplayInputWire(
        move_x=float(move_x_raw),
        move_y=float(move_y_raw),
        aim_x=float(aim_x_raw),
        aim_y=float(aim_y_raw),
        flags=int(flags_raw),
    )


def _event_to_wire(event: ReplayEvent) -> _ReplayEventWire:
    if isinstance(event, PerkPickEvent):
        return _PerkPickEventWire(
            tick_index=int(event.tick_index),
            player_index=int(event.player_index),
            choice_index=int(event.choice_index),
        )
    if isinstance(event, PerkMenuOpenEvent):
        return _PerkMenuOpenEventWire(
            tick_index=int(event.tick_index),
            player_index=int(event.player_index),
        )
    if isinstance(event, CaptureBootstrapEvent):
        return _CaptureBootstrapEventWire(
            tick_index=int(event.tick_index),
            elapsed_ms=int(event.elapsed_ms),
            score_xp=int(event.score_xp),
            perk_pending=int(event.perk_pending),
            perk_pending_count=int(event.perk_pending_count),
            perk_choices_dirty=bool(event.perk_choices_dirty),
            perk_choices=[int(value) for value in event.perk_choices],
            player_nonzero_counts=[
                [[int(perk_id), int(count)] for perk_id, count in player_counts]
                for player_counts in event.player_nonzero_counts
            ],
            players=[
                _CaptureBootstrapPlayerWire(
                    weapon_id=int(player.weapon_id),
                    pos_x=float(player.pos_x),
                    pos_y=float(player.pos_y),
                    health=float(player.health),
                    ammo=float(player.ammo),
                    experience=int(player.experience),
                    level=int(player.level),
                    clip_size=int(player.clip_size) if player.clip_size is not None else None,
                    reload_active=bool(player.reload_active) if player.reload_active is not None else None,
                    reload_timer=float(player.reload_timer) if player.reload_timer is not None else None,
                    reload_timer_max=float(player.reload_timer_max) if player.reload_timer_max is not None else None,
                    shot_cooldown=float(player.shot_cooldown) if player.shot_cooldown is not None else None,
                    spread_heat=float(player.spread_heat) if player.spread_heat is not None else None,
                    aim_x=float(player.aim_x) if player.aim_x is not None else None,
                    aim_y=float(player.aim_y) if player.aim_y is not None else None,
                    aim_heading=float(player.aim_heading) if player.aim_heading is not None else None,
                    alt_weapon_id=int(player.alt_weapon_id) if player.alt_weapon_id is not None else None,
                    alt_clip_size=int(player.alt_clip_size) if player.alt_clip_size is not None else None,
                    alt_ammo=float(player.alt_ammo) if player.alt_ammo is not None else None,
                    alt_reload_active=bool(player.alt_reload_active) if player.alt_reload_active is not None else None,
                    alt_reload_timer=float(player.alt_reload_timer) if player.alt_reload_timer is not None else None,
                    alt_reload_timer_max=float(player.alt_reload_timer_max)
                    if player.alt_reload_timer_max is not None
                    else None,
                    alt_shot_cooldown=float(player.alt_shot_cooldown) if player.alt_shot_cooldown is not None else None,
                    shield_ms=int(player.shield_ms) if player.shield_ms is not None else None,
                    fire_bullets_ms=int(player.fire_bullets_ms) if player.fire_bullets_ms is not None else None,
                    speed_bonus_ms=int(player.speed_bonus_ms) if player.speed_bonus_ms is not None else None,
                    hot_tempered_timer=float(player.hot_tempered_timer)
                    if player.hot_tempered_timer is not None
                    else None,
                    man_bomb_timer=float(player.man_bomb_timer) if player.man_bomb_timer is not None else None,
                    living_fortress_timer=float(player.living_fortress_timer)
                    if player.living_fortress_timer is not None
                    else None,
                    fire_cough_timer=float(player.fire_cough_timer) if player.fire_cough_timer is not None else None,
                )
                for player in event.players
            ],
            digital_move_enabled_by_player=[bool(value) for value in event.digital_move_enabled_by_player],
            weapon_power_up_ms=int(event.weapon_power_up_ms),
            reflex_boost_ms=int(event.reflex_boost_ms),
            energizer_ms=int(event.energizer_ms),
            double_experience_ms=int(event.double_experience_ms),
            freeze_ms=int(event.freeze_ms),
            perk_interval_man_bomb=(
                float(event.perk_interval_man_bomb) if event.perk_interval_man_bomb is not None else None
            ),
            perk_interval_fire_cough=(
                float(event.perk_interval_fire_cough) if event.perk_interval_fire_cough is not None else None
            ),
            perk_interval_hot_tempered=(
                float(event.perk_interval_hot_tempered) if event.perk_interval_hot_tempered is not None else None
            ),
            quest_session=(
                _CaptureBootstrapQuestSessionWire(
                    spawn_timeline_ms=(
                        float(event.quest_session.spawn_timeline_ms)
                        if event.quest_session.spawn_timeline_ms is not None
                        else None
                    ),
                    no_creatures_timer_ms=(
                        float(event.quest_session.no_creatures_timer_ms)
                        if event.quest_session.no_creatures_timer_ms is not None
                        else None
                    ),
                    completion_transition_ms=(
                        float(event.quest_session.completion_transition_ms)
                        if event.quest_session.completion_transition_ms is not None
                        else None
                    ),
                )
                if event.quest_session is not None
                else None
            ),
        )
    if isinstance(event, CapturePerkApplyEvent):
        return _CapturePerkApplyEventWire(
            tick_index=int(event.tick_index),
            perk_id=int(event.perk_id),
            outside_before=bool(event.outside_before),
            pending_before=int(event.pending_before) if event.pending_before is not None else None,
            pending_after=int(event.pending_after) if event.pending_after is not None else None,
        )
    if isinstance(event, CapturePerkPendingEvent):
        return _CapturePerkPendingEventWire(
            tick_index=int(event.tick_index),
            perk_pending=int(event.perk_pending),
        )
    if isinstance(event, CaptureCreatureSpawnEvent):
        return _CaptureCreatureSpawnEventWire(
            tick_index=int(event.tick_index),
            spawns=[
                _CaptureCreatureSpawnRowWire(
                    template_id=int(row.template_id),
                    pos_x=float(row.pos_x),
                    pos_y=float(row.pos_y),
                    heading=float(row.heading),
                )
                for row in event.spawns
            ],
            added_head=[
                _CaptureCreatureSpawnAddedHeadRowWire(
                    index=int(row.index),
                    heading=float(row.heading) if row.heading is not None else None,
                    target_heading=float(row.target_heading) if row.target_heading is not None else None,
                    ai_mode=int(row.ai_mode) if row.ai_mode is not None else None,
                    link_index=int(row.link_index) if row.link_index is not None else None,
                    hp=float(row.hp) if row.hp is not None else None,
                    lifecycle_stage=float(row.lifecycle_stage) if row.lifecycle_stage is not None else None,
                    orbit_angle=float(row.orbit_angle) if row.orbit_angle is not None else None,
                    orbit_radius=float(row.orbit_radius) if row.orbit_radius is not None else None,
                    flags=int(row.flags) if row.flags is not None else None,
                    type_id=int(row.type_id) if row.type_id is not None else None,
                    pos_x=float(row.pos_x) if row.pos_x is not None else None,
                    pos_y=float(row.pos_y) if row.pos_y is not None else None,
                )
                for row in event.added_head
            ],
        )
    if isinstance(event, CaptureStateTransitionEvent):
        return _CaptureStateTransitionEventWire(
            tick_index=int(event.tick_index),
            transitions=[
                _CaptureStateTransitionRowWire(
                    target_state=int(row.target_state),
                    before_state=int(row.before_state) if row.before_state is not None else None,
                    after_state=int(row.after_state) if row.after_state is not None else None,
                )
                for row in event.transitions
            ],
        )
    raise ReplayCodecError(f"unsupported event type: {type(event).__name__}")  # pragma: no cover


def _event_from_wire(event: _ReplayEventWire) -> ReplayEvent:
    if isinstance(event, _PerkPickEventWire):
        if int(event.player_index) < 0 or int(event.choice_index) < 0:
            raise ReplayCodecError("perk_pick must have non-negative player/choice indexes")
        return PerkPickEvent(
            tick_index=int(event.tick_index),
            player_index=int(event.player_index),
            choice_index=int(event.choice_index),
        )
    if isinstance(event, _PerkMenuOpenEventWire):
        if int(event.player_index) < 0:
            raise ReplayCodecError(f"perk_menu_open must have non-negative player index: {event.player_index}")
        return PerkMenuOpenEvent(
            tick_index=int(event.tick_index),
            player_index=int(event.player_index),
        )
    if isinstance(event, _CaptureBootstrapEventWire):
        return CaptureBootstrapEvent(
            tick_index=int(event.tick_index),
            elapsed_ms=int(event.elapsed_ms),
            score_xp=int(event.score_xp),
            perk_pending=int(event.perk_pending),
            perk_pending_count=int(event.perk_pending_count),
            perk_choices_dirty=bool(event.perk_choices_dirty),
            perk_choices=[int(value) for value in event.perk_choices],
            player_nonzero_counts=[
                [[int(perk_id), int(count)] for perk_id, count in player_counts]
                for player_counts in event.player_nonzero_counts
            ],
            players=[
                CaptureBootstrapPlayer(
                    weapon_id=int(player.weapon_id),
                    pos_x=float(player.pos_x),
                    pos_y=float(player.pos_y),
                    health=float(player.health),
                    ammo=float(player.ammo),
                    experience=int(player.experience),
                    level=int(player.level),
                    clip_size=int(player.clip_size) if player.clip_size is not None else None,
                    reload_active=bool(player.reload_active) if player.reload_active is not None else None,
                    reload_timer=float(player.reload_timer) if player.reload_timer is not None else None,
                    reload_timer_max=float(player.reload_timer_max) if player.reload_timer_max is not None else None,
                    shot_cooldown=float(player.shot_cooldown) if player.shot_cooldown is not None else None,
                    spread_heat=float(player.spread_heat) if player.spread_heat is not None else None,
                    aim_x=float(player.aim_x) if player.aim_x is not None else None,
                    aim_y=float(player.aim_y) if player.aim_y is not None else None,
                    aim_heading=float(player.aim_heading) if player.aim_heading is not None else None,
                    alt_weapon_id=int(player.alt_weapon_id) if player.alt_weapon_id is not None else None,
                    alt_clip_size=int(player.alt_clip_size) if player.alt_clip_size is not None else None,
                    alt_ammo=float(player.alt_ammo) if player.alt_ammo is not None else None,
                    alt_reload_active=bool(player.alt_reload_active) if player.alt_reload_active is not None else None,
                    alt_reload_timer=float(player.alt_reload_timer) if player.alt_reload_timer is not None else None,
                    alt_reload_timer_max=float(player.alt_reload_timer_max)
                    if player.alt_reload_timer_max is not None
                    else None,
                    alt_shot_cooldown=float(player.alt_shot_cooldown) if player.alt_shot_cooldown is not None else None,
                    shield_ms=int(player.shield_ms) if player.shield_ms is not None else None,
                    fire_bullets_ms=int(player.fire_bullets_ms) if player.fire_bullets_ms is not None else None,
                    speed_bonus_ms=int(player.speed_bonus_ms) if player.speed_bonus_ms is not None else None,
                    hot_tempered_timer=float(player.hot_tempered_timer)
                    if player.hot_tempered_timer is not None
                    else None,
                    man_bomb_timer=float(player.man_bomb_timer) if player.man_bomb_timer is not None else None,
                    living_fortress_timer=float(player.living_fortress_timer)
                    if player.living_fortress_timer is not None
                    else None,
                    fire_cough_timer=float(player.fire_cough_timer) if player.fire_cough_timer is not None else None,
                )
                for player in event.players
            ],
            digital_move_enabled_by_player=[bool(value) for value in event.digital_move_enabled_by_player],
            weapon_power_up_ms=int(event.weapon_power_up_ms),
            reflex_boost_ms=int(event.reflex_boost_ms),
            energizer_ms=int(event.energizer_ms),
            double_experience_ms=int(event.double_experience_ms),
            freeze_ms=int(event.freeze_ms),
            perk_interval_man_bomb=(
                float(event.perk_interval_man_bomb) if event.perk_interval_man_bomb is not None else None
            ),
            perk_interval_fire_cough=(
                float(event.perk_interval_fire_cough) if event.perk_interval_fire_cough is not None else None
            ),
            perk_interval_hot_tempered=(
                float(event.perk_interval_hot_tempered) if event.perk_interval_hot_tempered is not None else None
            ),
            quest_session=(
                CaptureBootstrapQuestSession(
                    spawn_timeline_ms=(
                        float(event.quest_session.spawn_timeline_ms)
                        if event.quest_session.spawn_timeline_ms is not None
                        else None
                    ),
                    no_creatures_timer_ms=(
                        float(event.quest_session.no_creatures_timer_ms)
                        if event.quest_session.no_creatures_timer_ms is not None
                        else None
                    ),
                    completion_transition_ms=(
                        float(event.quest_session.completion_transition_ms)
                        if event.quest_session.completion_transition_ms is not None
                        else None
                    ),
                )
                if event.quest_session is not None
                else None
            ),
        )
    if isinstance(event, _CapturePerkApplyEventWire):
        return CapturePerkApplyEvent(
            tick_index=int(event.tick_index),
            perk_id=int(event.perk_id),
            outside_before=bool(event.outside_before),
            pending_before=int(event.pending_before) if event.pending_before is not None else None,
            pending_after=int(event.pending_after) if event.pending_after is not None else None,
        )
    if isinstance(event, _CapturePerkPendingEventWire):
        return CapturePerkPendingEvent(
            tick_index=int(event.tick_index),
            perk_pending=int(event.perk_pending),
        )
    if isinstance(event, _CaptureCreatureSpawnEventWire):
        return CaptureCreatureSpawnEvent(
            tick_index=int(event.tick_index),
            spawns=[
                CaptureCreatureSpawnRow(
                    template_id=int(row.template_id),
                    pos_x=float(row.pos_x),
                    pos_y=float(row.pos_y),
                    heading=float(row.heading),
                )
                for row in event.spawns
            ],
            added_head=[
                CaptureCreatureSpawnAddedHeadRow(
                    index=int(row.index),
                    heading=float(row.heading) if row.heading is not None else None,
                    target_heading=float(row.target_heading) if row.target_heading is not None else None,
                    ai_mode=int(row.ai_mode) if row.ai_mode is not None else None,
                    link_index=int(row.link_index) if row.link_index is not None else None,
                    hp=float(row.hp) if row.hp is not None else None,
                    lifecycle_stage=float(row.lifecycle_stage) if row.lifecycle_stage is not None else None,
                    orbit_angle=float(row.orbit_angle) if row.orbit_angle is not None else None,
                    orbit_radius=float(row.orbit_radius) if row.orbit_radius is not None else None,
                    flags=int(row.flags) if row.flags is not None else None,
                    type_id=int(row.type_id) if row.type_id is not None else None,
                    pos_x=float(row.pos_x) if row.pos_x is not None else None,
                    pos_y=float(row.pos_y) if row.pos_y is not None else None,
                )
                for row in event.added_head
            ],
        )
    if isinstance(event, _CaptureStateTransitionEventWire):
        return CaptureStateTransitionEvent(
            tick_index=int(event.tick_index),
            transitions=[
                CaptureStateTransitionRow(
                    target_state=int(row.target_state),
                    before_state=int(row.before_state) if row.before_state is not None else None,
                    after_state=int(row.after_state) if row.after_state is not None else None,
                )
                for row in event.transitions
            ],
        )
    raise ReplayCodecError(f"unsupported replay event wire type: {type(event).__name__}")


def dump_replay(replay: Replay) -> bytes:
    """Serialize a replay as a gzipped msgpack blob.

    The gzip header is written with mtime=0 for stable content hashing.
    """

    header_wire = _header_to_wire(replay.header)
    inputs_wire: list[list[_ReplayInputWire]] = []
    expected_players = int(replay.header.player_count)
    for tick_idx, tick in enumerate(replay.inputs):
        if len(tick) != expected_players:
            raise ReplayCodecError(
                f"replay tick {tick_idx} has {len(tick)} players, expected {expected_players}",
            )
        inputs_wire.append(
            [
                _packed_input_to_wire(packed, tick_idx=int(tick_idx), player_idx=int(player_idx))
                for player_idx, packed in enumerate(tick)
            ],
        )

    events_wire = [_event_to_wire(event) for event in replay.events]
    wire = _ReplayWire(header=header_wire, inputs=inputs_wire, events=events_wire)
    raw = msgspec.msgpack.encode(wire)
    return gzip.compress(raw, compresslevel=9, mtime=0)


def load_replay(data: bytes) -> Replay:
    max_payload_bytes = int(_max_replay_payload_bytes())
    if _is_gzip(data):
        data = _decompress_gzip_replay(data, max_output_bytes=max_payload_bytes)
    if len(data) > int(max_payload_bytes):
        raise ReplayCodecError(f"replay payload too large (> {int(max_payload_bytes)} bytes)")

    stripped = data.lstrip()
    if stripped.startswith((b"{", b"[")):
        raise ReplayCodecError("legacy JSON replay format is unsupported; regenerate the replay")

    try:
        wire = _REPLAY_DECODER.decode(data)
    except (msgspec.DecodeError, msgspec.ValidationError) as exc:
        raise ReplayCodecError("invalid replay msgpack payload") from exc

    header = _header_from_wire(wire.header)

    expected_players = int(header.player_count)
    inputs: list[PackedTickInputs] = []
    for tick_idx, tick in enumerate(wire.inputs):
        if len(tick) != expected_players:
            raise ReplayCodecError(
                f"replay tick {tick_idx} has {len(tick)} players, expected {expected_players}",
            )
        packed_tick: PackedTickInputs = []
        for packed in tick:
            move_x = float(packed.move_x)
            move_y = float(packed.move_y)
            aim_x = float(packed.aim_x)
            aim_y = float(packed.aim_y)
            flags = int(packed.flags)
            move_x = _quantize_f32(move_x)
            move_y = _quantize_f32(move_y)
            aim_x = _quantize_f32(aim_x)
            aim_y = _quantize_f32(aim_y)
            packed_tick.append([move_x, move_y, aim_x, aim_y, flags])
        inputs.append(packed_tick)

    events = [_event_from_wire(event) for event in wire.events]
    input_len = len(inputs)
    for event in events:
        tick_index = event.tick_index
        if tick_index < 0:
            raise ReplayCodecError(f"replay event tick_index must be non-negative, got {tick_index}")
        if tick_index > input_len:
            raise ReplayCodecError(f"replay event tick_index out of bounds: {tick_index} > {input_len}")

    return Replay(header=header, inputs=inputs, events=events)


def dump_replay_file(path: Path, replay: Replay) -> None:
    path = Path(path)
    path.write_bytes(dump_replay(replay))


def load_replay_file(path: Path) -> Replay:
    path = Path(path)
    return load_replay(path.read_bytes())
