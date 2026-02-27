from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, TypeAlias

REPLAY_FORMAT_VERSION = 6
ReplayFormatVersion: TypeAlias = Literal[6]

BootstrapKind: TypeAlias = Literal["none", "terrain_v1"]

WEAPON_USAGE_COUNT = 53

FIRE_DOWN_FLAG = 1 << 0
FIRE_PRESSED_FLAG = 1 << 1
RELOAD_PRESSED_FLAG = 1 << 2
MOVE_KEYS_PRESENT_FLAG = 1 << 3
MOVE_FORWARD_FLAG = 1 << 4
MOVE_BACKWARD_FLAG = 1 << 5
TURN_LEFT_FLAG = 1 << 6
TURN_RIGHT_FLAG = 1 << 7
MOVE_MODE_PRESENT_FLAG = 1 << 8
MOVE_MODE_SHIFT = 9
MOVE_MODE_MASK = 0x7
AIM_SCHEME_PRESENT_FLAG = 1 << 12
AIM_SCHEME_SHIFT = 13
AIM_SCHEME_MASK = 0x7

InputQuantization: TypeAlias = Literal["f32"]

CAPTURE_BOOTSTRAP_EVENT_KIND = "orig_capture_bootstrap"
CAPTURE_PERK_PENDING_EVENT_KIND = "orig_capture_perk_pending"
CAPTURE_PERK_APPLY_EVENT_KIND = "orig_capture_perk_apply"
CAPTURE_CREATURE_SPAWN_EVENT_KIND = "orig_capture_creature_spawn"
CAPTURE_STATE_TRANSITION_EVENT_KIND = "orig_capture_state_transition"


def _default_game_version() -> str:
    from .. import __version__

    return str(__version__)


def pack_input_flags(
    *,
    fire_down: bool,
    fire_pressed: bool,
    reload_pressed: bool,
    move_mode: int | None = None,
    aim_scheme: int | None = None,
    move_forward_pressed: bool | None = None,
    move_backward_pressed: bool | None = None,
    turn_left_pressed: bool | None = None,
    turn_right_pressed: bool | None = None,
) -> int:
    flags = 0
    if fire_down:
        flags |= FIRE_DOWN_FLAG
    if fire_pressed:
        flags |= FIRE_PRESSED_FLAG
    if reload_pressed:
        flags |= RELOAD_PRESSED_FLAG
    key_fields = (
        move_forward_pressed,
        move_backward_pressed,
        turn_left_pressed,
        turn_right_pressed,
    )
    if any(field is not None for field in key_fields):
        flags |= MOVE_KEYS_PRESENT_FLAG
        if bool(move_forward_pressed):
            flags |= MOVE_FORWARD_FLAG
        if bool(move_backward_pressed):
            flags |= MOVE_BACKWARD_FLAG
        if bool(turn_left_pressed):
            flags |= TURN_LEFT_FLAG
        if bool(turn_right_pressed):
            flags |= TURN_RIGHT_FLAG
    if move_mode is not None:
        flags |= MOVE_MODE_PRESENT_FLAG
        flags |= (int(move_mode) & MOVE_MODE_MASK) << MOVE_MODE_SHIFT
    if aim_scheme is not None:
        flags |= AIM_SCHEME_PRESENT_FLAG
        flags |= (int(aim_scheme) & AIM_SCHEME_MASK) << AIM_SCHEME_SHIFT
    return int(flags)


def unpack_input_flags(flags: int) -> tuple[bool, bool, bool]:
    flags = int(flags)
    return (
        bool(flags & FIRE_DOWN_FLAG),
        bool(flags & FIRE_PRESSED_FLAG),
        bool(flags & RELOAD_PRESSED_FLAG),
    )


def unpack_input_move_key_flags(flags: int) -> tuple[bool | None, bool | None, bool | None, bool | None]:
    flags = int(flags)
    if not bool(flags & MOVE_KEYS_PRESENT_FLAG):
        return None, None, None, None
    return (
        bool(flags & MOVE_FORWARD_FLAG),
        bool(flags & MOVE_BACKWARD_FLAG),
        bool(flags & TURN_LEFT_FLAG),
        bool(flags & TURN_RIGHT_FLAG),
    )


def unpack_input_mode_flags(flags: int) -> tuple[int | None, int | None]:
    flags = int(flags)
    move_mode: int | None = None
    aim_scheme: int | None = None
    if bool(flags & MOVE_MODE_PRESENT_FLAG):
        move_mode = (flags >> MOVE_MODE_SHIFT) & MOVE_MODE_MASK
    if bool(flags & AIM_SCHEME_PRESENT_FLAG):
        aim_scheme = (flags >> AIM_SCHEME_SHIFT) & AIM_SCHEME_MASK
        if aim_scheme == AIM_SCHEME_MASK:
            aim_scheme = -1
    return move_mode, aim_scheme


PackedPlayerInput: TypeAlias = list[float | int]
PackedTickInputs: TypeAlias = list[PackedPlayerInput]


def unpack_packed_player_input(packed: PackedPlayerInput) -> tuple[float, float, float, float, int]:
    """Decode a compact replay input row into scalar values.

    Stored shape is `[move_x, move_y, aim_x, aim_y, flags]`.
    Returns `(move_x, move_y, aim_x, aim_y, flags)`.
    """

    def _require_num_f(value: object, *, field: str) -> float:
        if isinstance(value, bool):
            raise TypeError(f"{field} must be numeric, got bool")
        if isinstance(value, (int, float)):
            return float(value)
        raise TypeError(f"{field} must be numeric")

    def _require_num_i(value: object, *, field: str) -> int:
        if isinstance(value, bool):
            raise TypeError(f"{field} must be numeric, got bool")
        if isinstance(value, int):
            return int(value)
        if isinstance(value, float):
            return int(value)
        raise TypeError(f"{field} must be numeric")

    if len(packed) != 5:
        raise ValueError(f"packed replay input must have 5 fields, got {len(packed)}")

    mx = _require_num_f(packed[0], field="move_x")
    my = _require_num_f(packed[1], field="move_y")
    ax = _require_num_f(packed[2], field="aim_x")
    ay = _require_num_f(packed[3], field="aim_y")
    flags = _require_num_i(packed[4], field="flags")

    return mx, my, ax, ay, flags


@dataclass(frozen=True, slots=True)
class ReplayStatusSnapshot:
    quest_unlock_index: int = 0
    quest_unlock_index_full: int = 0
    weapon_usage_counts: tuple[int, ...] = field(default_factory=lambda: (0,) * WEAPON_USAGE_COUNT)


@dataclass(frozen=True, slots=True)
class ReplayClaimedStatsSnapshot:
    complete: bool = False
    ticks: int = 0
    elapsed_ms: int = 0
    score_xp: int = 0
    kills: int = 0
    most_used_weapon_id: int = 0
    shots_fired: int = 0
    shots_hit: int = 0


@dataclass(frozen=True, slots=True)
class ReplayHeader:
    game_mode_id: int
    seed: int
    replay_format_version: int = REPLAY_FORMAT_VERSION
    # Quests can recover their spawn script deterministically from the level id.
    # Leave empty for non-quest modes or legacy replays.
    quest_level: str = ""
    bootstrap_kind: BootstrapKind = "none"
    bootstrap_seed: int = 0
    game_version: str = field(default_factory=_default_game_version)
    tick_rate: int = 60
    difficulty_level: int = 0
    hardcore: bool = False
    preserve_bugs: bool = False
    detail_preset: int = 5
    fx_toggle: int = 0
    world_size: float = 1024.0
    player_count: int = 1
    status: ReplayStatusSnapshot = field(default_factory=ReplayStatusSnapshot)
    claimed_stats: ReplayClaimedStatsSnapshot = field(default_factory=ReplayClaimedStatsSnapshot)
    input_quantization: InputQuantization = "f32"


@dataclass(frozen=True, slots=True)
class PerkPickEvent:
    tick_index: int
    player_index: int
    choice_index: int


@dataclass(frozen=True, slots=True)
class PerkMenuOpenEvent:
    tick_index: int
    player_index: int


@dataclass(frozen=True, slots=True)
class CaptureBootstrapQuestSession:
    spawn_timeline_ms: float | None
    no_creatures_timer_ms: float | None
    completion_transition_ms: float | None


@dataclass(frozen=True, slots=True)
class CaptureBootstrapPlayer:
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


@dataclass(frozen=True, slots=True)
class CaptureBootstrapEvent:
    tick_index: int
    elapsed_ms: int
    score_xp: int
    perk_pending: int
    perk_pending_count: int
    perk_choices_dirty: bool
    perk_choices: list[int]
    player_nonzero_counts: list[list[list[int]]]
    players: list[CaptureBootstrapPlayer]
    digital_move_enabled_by_player: list[bool]
    weapon_power_up_ms: int
    reflex_boost_ms: int
    energizer_ms: int
    double_experience_ms: int
    freeze_ms: int
    perk_interval_man_bomb: float | None
    perk_interval_fire_cough: float | None
    perk_interval_hot_tempered: float | None
    quest_session: CaptureBootstrapQuestSession | None


@dataclass(frozen=True, slots=True)
class CapturePerkApplyEvent:
    tick_index: int
    perk_id: int
    outside_before: bool
    pending_before: int | None
    pending_after: int | None


@dataclass(frozen=True, slots=True)
class CapturePerkPendingEvent:
    tick_index: int
    perk_pending: int


@dataclass(frozen=True, slots=True)
class CaptureCreatureSpawnRow:
    template_id: int
    pos_x: float
    pos_y: float
    heading: float


@dataclass(frozen=True, slots=True)
class CaptureCreatureSpawnAddedHeadRow:
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


@dataclass(frozen=True, slots=True)
class CaptureCreatureSpawnEvent:
    tick_index: int
    spawns: list[CaptureCreatureSpawnRow]
    added_head: list[CaptureCreatureSpawnAddedHeadRow]


@dataclass(frozen=True, slots=True)
class CaptureStateTransitionRow:
    target_state: int
    before_state: int | None
    after_state: int | None


@dataclass(frozen=True, slots=True)
class CaptureStateTransitionEvent:
    tick_index: int
    transitions: list[CaptureStateTransitionRow]


ReplayEvent: TypeAlias = (
    PerkPickEvent
    | PerkMenuOpenEvent
    | CaptureBootstrapEvent
    | CapturePerkApplyEvent
    | CapturePerkPendingEvent
    | CaptureCreatureSpawnEvent
    | CaptureStateTransitionEvent
)


@dataclass(slots=True)
class Replay:
    header: ReplayHeader
    inputs: list[PackedTickInputs]
    events: list[ReplayEvent] = field(default_factory=list)
