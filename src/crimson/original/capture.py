from __future__ import annotations

from collections.abc import Iterable, Mapping
import gzip
import math
from pathlib import Path
import struct

import msgspec
from grim.geom import Vec2

from ..bonuses import BonusId
from ..game_modes import GameMode
from ..replay.checkpoints import (
    FORMAT_VERSION,
    ReplayCheckpoint,
    ReplayCheckpoints,
    ReplayDeathLedgerEntry,
    ReplayEventSummary,
    ReplayPerkSnapshot,
    ReplayPlayerCheckpoint,
)
from ..replay.types import (
    PerkMenuOpenEvent,
    Replay,
    ReplayHeader,
    ReplayStatusSnapshot,
    UnknownEvent,
    WEAPON_USAGE_COUNT,
    pack_input_flags,
)
from .schema import (
    CAPTURE_FORMAT_VERSION,
    CaptureEventHeadBonusApply,
    CaptureEventHeadPerkApply,
    CaptureEventHeadPerkDelta,
    CaptureEventHeadProjectileSpawn,
    CaptureEventHeadSecondaryProjectileSpawn,
    CaptureFile,
    CapturePlayerCheckpoint,
    CaptureTick,
)

CAPTURE_UNKNOWN_INT = -1
CAPTURE_BOOTSTRAP_EVENT_KIND = "orig_capture_bootstrap"
CAPTURE_PERK_PENDING_EVENT_KIND = "orig_capture_perk_pending"
CAPTURE_PERK_APPLY_EVENT_KIND = "orig_capture_perk_apply"

_CRT_RAND_MULT = 214013
_CRT_RAND_INC = 2531011
_CRT_RAND_MOD_MASK = 0xFFFFFFFF
_CRT_RAND_INV_MULT = pow(_CRT_RAND_MULT, -1, 1 << 32)
_AIM_SCHEME_COMPUTER = 5
_PLAYER_PROJECTILE_OWNER_SENTINEL = -100
_PROJECTILE_TYPE_FIRE_BULLETS = 45
_PROJECTILE_SPAWNING_BONUS_IDS = frozenset(
    {
        int(BonusId.FIREBLAST),
        int(BonusId.SHOCK_CHAIN),
        int(BonusId.NUKE),
    }
)


class CaptureError(ValueError):
    pass


class _CapturePerkApplyPayload(msgspec.Struct, forbid_unknown_fields=True):
    perk_id: int
    outside_before: bool = False


class _CapturePerkPendingPayload(msgspec.Struct, forbid_unknown_fields=True):
    perk_pending: int


class _CaptureStreamMetaRow(msgspec.Struct, tag="capture_meta", tag_field="event", forbid_unknown_fields=True):
    capture: CaptureFile


class _CaptureStreamTickRow(msgspec.Struct, tag="tick", tag_field="event", forbid_unknown_fields=True):
    tick: CaptureTick


_CaptureStreamRow = _CaptureStreamMetaRow | _CaptureStreamTickRow
_F32_TOKEN_PREFIX = "f32:"


def _coerce_int_like(value: object) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def parse_player_int_overrides(entries: Iterable[str] | None, *, option_name: str) -> dict[int, int]:
    out: dict[int, int] = {}
    if entries is None:
        return out

    for raw_entry in entries:
        entry = str(raw_entry).strip()
        if not entry:
            continue
        if "=" in entry:
            player_text, value_text = entry.split("=", 1)
        elif ":" in entry:
            player_text, value_text = entry.split(":", 1)
        else:
            raise ValueError(
                f"{option_name} expects PLAYER=VALUE (or PLAYER:VALUE), got {entry!r}"
            )

        player_index = _coerce_int_like(player_text.strip())
        value = _coerce_int_like(value_text.strip())
        if player_index is None or int(player_index) < 0:
            raise ValueError(f"{option_name} has invalid player index in {entry!r}")
        if value is None:
            raise ValueError(f"{option_name} has invalid value in {entry!r}")
        out[int(player_index)] = int(value)

    return out


def _f32_from_u32(value: int) -> float:
    return struct.unpack("<f", struct.pack("<I", int(value) & 0xFFFFFFFF))[0]


def _decode_f32_token(value: object) -> object:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text.startswith(_F32_TOKEN_PREFIX):
        return value
    raw = text[len(_F32_TOKEN_PREFIX) :].strip()
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    if len(raw) != 8:
        raise CaptureError(f"invalid f32 token width: {value!r}")
    try:
        bits = int(raw, 16)
    except ValueError as exc:
        raise CaptureError(f"invalid f32 token hex: {value!r}") from exc
    return float(_f32_from_u32(int(bits)))


def _decode_f32_tokens(value: object) -> object:
    if isinstance(value, dict):
        return {str(k): _decode_f32_tokens(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode_f32_tokens(item) for item in value]
    if isinstance(value, tuple):
        return [_decode_f32_tokens(item) for item in value]
    return _decode_f32_token(value)


def _float_or(value: object, default: float) -> float:
    if value is None:
        return float(default)
    try:
        return float(value)  # ty:ignore[invalid-argument-type]
    except (TypeError, ValueError):
        return float(default)


def _estimate_sample_rate(tick_indices: list[int]) -> int:
    if len(tick_indices) < 2:
        return 1
    deltas = [
        next_tick - tick
        for tick, next_tick in zip(tick_indices, tick_indices[1:])
        if int(next_tick) > int(tick)
    ]
    if not deltas:
        return 1
    deltas.sort()
    return max(1, int(deltas[len(deltas) // 2]))


def _tick_indices(capture: CaptureFile) -> list[int]:
    return sorted(int(tick.tick_index) for tick in capture.ticks)


def _capture_sample_rate(capture: CaptureFile) -> int:
    return _estimate_sample_rate(_tick_indices(capture))


def _replay_player(player: CapturePlayerCheckpoint) -> ReplayPlayerCheckpoint:
    return ReplayPlayerCheckpoint(
        pos=Vec2(float(player.pos.x), float(player.pos.y)),
        health=float(player.health),
        weapon_id=int(player.weapon_id),
        ammo=float(player.ammo),
        experience=int(player.experience),
        level=int(player.level),
    )


def _replay_death(raw: object) -> ReplayDeathLedgerEntry:
    if hasattr(raw, "creature_index"):
        return ReplayDeathLedgerEntry(
            creature_index=int(getattr(raw, "creature_index")),
            type_id=int(getattr(raw, "type_id")),
            reward_value=float(getattr(raw, "reward_value")),
            xp_awarded=int(getattr(raw, "xp_awarded")),
            owner_id=int(getattr(raw, "owner_id")),
        )
    return ReplayDeathLedgerEntry(
        creature_index=-1,
        type_id=-1,
        reward_value=0.0,
        xp_awarded=-1,
        owner_id=-1,
    )


def _replay_perk(raw: object) -> ReplayPerkSnapshot:
    if raw is None:
        return ReplayPerkSnapshot()

    pending_count = int(getattr(raw, "pending_count", 0))
    choices_dirty = bool(getattr(raw, "choices_dirty", False))
    choices_raw = getattr(raw, "choices", [])
    choices = [int(value) for value in choices_raw] if isinstance(choices_raw, list) else []

    player_nonzero_counts: list[list[list[int]]] = []
    counts_raw = getattr(raw, "player_nonzero_counts", [])
    if isinstance(counts_raw, list):
        for player_counts in counts_raw:
            if not isinstance(player_counts, list):
                player_nonzero_counts.append([])
                continue
            parsed_player: list[list[int]] = []
            for pair in player_counts:
                if isinstance(pair, (list, tuple)) and len(pair) == 2:
                    parsed_player.append([int(pair[0]), int(pair[1])])
            player_nonzero_counts.append(parsed_player)

    return ReplayPerkSnapshot(
        pending_count=int(pending_count),
        choices_dirty=bool(choices_dirty),
        choices=choices,
        player_nonzero_counts=player_nonzero_counts,
    )


def _replay_events(raw: object) -> ReplayEventSummary:
    if raw is None:
        return ReplayEventSummary(hit_count=-1, pickup_count=-1, sfx_count=-1, sfx_head=[])
    sfx_head_raw = getattr(raw, "sfx_head", [])
    sfx_head = [str(value) for value in sfx_head_raw] if isinstance(sfx_head_raw, list) else []
    return ReplayEventSummary(
        hit_count=int(getattr(raw, "hit_count", -1)),
        pickup_count=int(getattr(raw, "pickup_count", -1)),
        sfx_count=int(getattr(raw, "sfx_count", -1)),
        sfx_head=sfx_head[:4],
    )


def _rng_head_values(tick: CaptureTick) -> list[int]:
    out: list[int] = []
    sources = list(tick.rng.head)
    if not sources:
        sources = list(tick.checkpoint.rng_marks.rand_head)
    for item in sources:
        value: int | None = None
        if item.value_15 is not None:
            value = int(item.value_15)
        elif item.value is not None:
            value = int(item.value) & 0x7FFF
        if value is None:
            continue
        if 0 <= int(value) <= 0x7FFF:
            out.append(int(value))
    return out


def _infer_seed_from_rng_state_before(tick: CaptureTick) -> int | None:
    sources = list(tick.rng.head)
    if not sources:
        sources = list(tick.checkpoint.rng_marks.rand_head)
    if not sources:
        return None

    rng_head = _rng_head_values(tick)
    marks = tick.checkpoint.rng_marks
    rand_calls: object = int(marks.rand_calls)
    rand_last: object = marks.rand_last
    if int(rand_calls) <= 0 and int(tick.rng.calls) > 0:
        rand_calls = int(tick.rng.calls)
    if rand_last is None:
        rand_last = tick.rng.last_value

    for item in sources:
        state_before_u32 = item.state_before_u32
        if state_before_u32 is None:
            parsed_from_hex = _coerce_int_like(item.state_before_hex)
            if parsed_from_hex is not None:
                state_before_u32 = int(parsed_from_hex)
        if state_before_u32 is None:
            continue
        candidate = int(state_before_u32) & _CRT_RAND_MOD_MASK
        if rng_head and not _seed_matches_rng_marks(
            int(candidate),
            rng_head=rng_head,
            rand_calls=rand_calls,
            rand_last=rand_last,
        ):
            continue
        return int(candidate)

    return None


def _rng_marks_int_map(tick: CaptureTick) -> dict[str, int]:
    marks = tick.checkpoint.rng_marks
    out: dict[str, int] = {}

    def put(name: str, value: int | None) -> None:
        if value is None:
            return
        out[name] = int(value)

    put("rand_calls", int(marks.rand_calls))
    put("rand_last", marks.rand_last)
    put("rand_seq_first", marks.rand_seq_first)
    put("rand_seq_last", marks.rand_seq_last)
    put("rand_seed_epoch_enter", marks.rand_seed_epoch_enter)
    put("rand_seed_epoch_last", marks.rand_seed_epoch_last)
    put("rand_outside_before_calls", int(marks.rand_outside_before_calls))
    put("rand_outside_before_dropped", int(marks.rand_outside_before_dropped))
    put("rand_mirror_mismatch_total", int(marks.rand_mirror_mismatch_total))
    put("rand_mirror_unknown_total", int(marks.rand_mirror_unknown_total))
    return out


def _tick_game_mode_id(tick: CaptureTick) -> int:
    if int(tick.game_mode_id) >= 0:
        return int(tick.game_mode_id)

    after_globals = tick.after.globals if tick.after is not None else {}
    game_mode = _coerce_int_like(after_globals.get("config_game_mode")) if isinstance(after_globals, dict) else None
    if game_mode is not None and int(game_mode) >= 0:
        return int(game_mode)

    before_globals = tick.before.globals if tick.before is not None else {}
    game_mode = _coerce_int_like(before_globals.get("config_game_mode")) if isinstance(before_globals, dict) else None
    if game_mode is not None and int(game_mode) >= 0:
        return int(game_mode)
    return -1


def _tick_frame_dt_ms(tick: CaptureTick) -> float | None:
    def _valid_dt_ms(value: object) -> float | None:
        if value is None:
            return None
        if not isinstance(value, (int, float)):
            return None
        candidate = float(value)
        if not math.isfinite(candidate):
            return None
        if candidate < 0.1 or candidate > 1000.0:
            return None
        return float(candidate)

    timing = tick.diagnostics.timing
    if isinstance(timing, dict):
        value = timing.get("frame_dt_after")
        if isinstance(value, (int, float)) and math.isfinite(float(value)) and float(value) > 0.0:
            validated = _valid_dt_ms(float(value) * 1000.0)
            if validated is not None:
                return float(validated)

    globals_obj: dict[str, object] = {}
    if tick.after is not None and isinstance(tick.after.globals, dict):
        globals_obj = tick.after.globals
    elif tick.before is not None and isinstance(tick.before.globals, dict):
        globals_obj = tick.before.globals

    if tick.frame_dt_ms_i32 is not None and int(tick.frame_dt_ms_i32) > 0:
        validated = _valid_dt_ms(int(tick.frame_dt_ms_i32))
        if validated is not None:
            return float(validated)

    dt_ms_i32 = _coerce_int_like(globals_obj.get("frame_dt_ms_i32"))
    if dt_ms_i32 is not None and int(dt_ms_i32) > 0:
        validated = _valid_dt_ms(int(dt_ms_i32))
        if validated is not None:
            return float(validated)

    validated_tick_dt = _valid_dt_ms(tick.frame_dt_ms)
    if validated_tick_dt is not None:
        return float(validated_tick_dt)

    validated_globals_dt = _valid_dt_ms(globals_obj.get("frame_dt_ms_f32"))
    if validated_globals_dt is not None:
        return float(validated_globals_dt)

    dt_seconds = globals_obj.get("frame_dt")
    if isinstance(dt_seconds, (int, float)) and math.isfinite(float(dt_seconds)):
        if 0.0 < float(dt_seconds) <= 1.0:
            validated = _valid_dt_ms(float(dt_seconds) * 1000.0)
            if validated is not None:
                return float(validated)

    timing = tick.diagnostics.timing
    if isinstance(timing, dict):
        value = timing.get("frame_dt_after")
        if isinstance(value, (int, float)) and math.isfinite(float(value)) and float(value) > 0.0:
            validated = _valid_dt_ms(float(value) * 1000.0)
            if validated is not None:
                return float(validated)

    return None


def _tick_frame_dt_ms_i32(tick: CaptureTick) -> int | None:
    if tick.frame_dt_ms_i32 is not None and int(tick.frame_dt_ms_i32) > 0:
        return int(tick.frame_dt_ms_i32)

    globals_obj: dict[str, object] = {}
    if tick.after is not None and isinstance(tick.after.globals, dict):
        globals_obj = tick.after.globals
    elif tick.before is not None and isinstance(tick.before.globals, dict):
        globals_obj = tick.before.globals

    value = _coerce_int_like(globals_obj.get("frame_dt_ms_i32"))
    if value is not None and int(value) > 0:
        return int(value)

    timing = tick.diagnostics.timing
    if isinstance(timing, dict):
        value = _coerce_int_like(timing.get("frame_dt_ms_after_i32"))
        if value is not None and int(value) > 0:
            return int(value)

    return None


def _infer_game_mode_id(capture: CaptureFile) -> int:
    for tick in capture.ticks:
        mode_id = _tick_game_mode_id(tick)
        if mode_id >= 0:
            return int(mode_id)

    mode_hint_to_game_mode = {
        "survival_update": int(GameMode.SURVIVAL),
        "rush_mode_update": int(GameMode.RUSH),
        "quest_mode_update": int(GameMode.QUESTS),
        "typo_gameplay_update_and_render": int(GameMode.TYPO),
    }
    for tick in capture.ticks:
        mode_hint = str(tick.mode_hint)
        if mode_hint in mode_hint_to_game_mode:
            return int(mode_hint_to_game_mode[mode_hint])
    return int(GameMode.SURVIVAL)


def _infer_player_count(capture: CaptureFile) -> int:
    player_count = 1
    for tick in capture.ticks:
        player_count = max(player_count, int(len(tick.checkpoint.players)))
        for sample in tick.input_approx:
            player_count = max(player_count, int(sample.player_index) + 1)
    return max(1, int(player_count))


def _infer_digital_move_enabled_by_player(capture: CaptureFile, *, player_count: int) -> list[bool]:
    size = max(1, int(player_count))
    saw_digital_keys: list[bool] = [False for _ in range(size)]

    for tick in capture.ticks:
        for key_row in tick.input_player_keys:
            player_index = int(key_row.player_index)
            if not (0 <= player_index < len(saw_digital_keys)):
                continue
            if (
                key_row.move_forward_pressed is not None
                or key_row.move_backward_pressed is not None
                or key_row.turn_left_pressed is not None
                or key_row.turn_right_pressed is not None
            ):
                saw_digital_keys[player_index] = True

    return [bool(enabled) for enabled in saw_digital_keys]


def _coerce_player_int(value: object, *, player_index: int) -> int | None:
    direct = _coerce_int_like(value)
    if direct is not None:
        return int(direct)
    if isinstance(value, (list, tuple)):
        if 0 <= int(player_index) < len(value):
            nested = _coerce_int_like(value[int(player_index)])
            if nested is not None:
                return int(nested)
        return None
    if isinstance(value, dict):
        key_text = str(int(player_index))
        preferred_key_texts = (
            key_text,
            f"player_{key_text}",
            f"player{key_text}",
            f"p{key_text}",
        )
        for raw_key, raw_value in value.items():
            if raw_key != int(player_index) and str(raw_key) not in preferred_key_texts:
                continue
            nested = _coerce_int_like(raw_value)
            if nested is not None:
                return int(nested)
    return None


def _tick_player_aim_scheme(tick: CaptureTick, *, player_index: int) -> int | None:
    for sample in tick.input_approx:
        if int(sample.player_index) != int(player_index):
            continue
        if sample.aim_scheme is None:
            continue
        parsed = _coerce_int_like(sample.aim_scheme)
        if parsed is not None:
            return int(parsed)

    for snapshot in (tick.after, tick.before):
        if snapshot is None:
            continue
        globals_obj = snapshot.globals if isinstance(snapshot.globals, dict) else {}
        globals_scheme = _coerce_player_int(
            globals_obj.get("config_aim_scheme"),
            player_index=int(player_index),
        )
        if globals_scheme is not None:
            return int(globals_scheme)
        input_obj = snapshot.input if isinstance(snapshot.input, dict) else {}
        input_scheme = _coerce_player_int(
            input_obj.get("config_aim_scheme"),
            player_index=int(player_index),
        )
        if input_scheme is not None:
            return int(input_scheme)
    return None


def _owner_id_to_player_index(owner_id: int, *, player_count: int) -> int | None:
    owner = int(owner_id)
    if -4 <= owner <= -1:
        player_index = -1 - int(owner)
        if 0 <= int(player_index) < int(player_count):
            return int(player_index)
    if int(owner) == _PLAYER_PROJECTILE_OWNER_SENTINEL and int(player_count) == 1:
        return 0
    return None


def _tick_player_projectile_spawn_count(tick: CaptureTick, *, player_index: int, player_count: int) -> int:
    total = 0
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadProjectileSpawn):
            continue
        owner_id = _coerce_int_like(head.data.get("owner_id"))
        if owner_id is None:
            continue
        owner_player_index = _owner_id_to_player_index(int(owner_id), player_count=int(player_count))
        if owner_player_index is None or int(owner_player_index) != int(player_index):
            continue
        total += 1
    return int(total)


def _tick_player_secondary_projectile_spawn_count(
    tick: CaptureTick,
    *,
    player_index: int,
    player_count: int,
) -> int:
    total = 0
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadSecondaryProjectileSpawn):
            continue
        owner_id = _coerce_int_like(head.data.get("owner_id"))
        if owner_id is not None:
            owner_player_index = _owner_id_to_player_index(int(owner_id), player_count=int(player_count))
            if owner_player_index is None or int(owner_player_index) != int(player_index):
                continue
            total += 1
            continue
        if int(player_count) == 1 and int(player_index) == 0:
            # Older captures did not include owner IDs on secondary spawns.
            total += 1
    return int(total)


def _tick_player_weapon_projectile_spawned(
    tick: CaptureTick,
    *,
    player_index: int,
    player_count: int,
    weapon_id: int,
) -> bool:
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadProjectileSpawn):
            continue
        owner_id = _coerce_int_like(head.data.get("owner_id"))
        if owner_id is None:
            continue
        owner_player_index = _owner_id_to_player_index(int(owner_id), player_count=int(player_count))
        if owner_player_index is None or int(owner_player_index) != int(player_index):
            continue
        requested_type = _coerce_int_like(head.data.get("requested_type_id"))
        actual_type = _coerce_int_like(head.data.get("actual_type_id"))
        if requested_type is not None and int(requested_type) == int(weapon_id):
            return True
        if actual_type is not None and int(actual_type) == int(weapon_id):
            return True
    return False


def _tick_player_projectile_bonus_apply(
    tick: CaptureTick,
    *,
    player_index: int,
    player_count: int,
) -> bool:
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadBonusApply):
            continue
        bonus_id = _coerce_int_like(head.data.get("bonus_id"))
        if bonus_id is None or int(bonus_id) not in _PROJECTILE_SPAWNING_BONUS_IDS:
            continue
        applied_player_index = _coerce_int_like(head.data.get("player_index"))
        if applied_player_index is None:
            if int(player_count) == 1 and int(player_index) == 0:
                return True
            continue
        if int(applied_player_index) == int(player_index):
            return True
    return False


def _tick_player_projectile_type_spawned(
    tick: CaptureTick,
    *,
    player_index: int,
    player_count: int,
    projectile_type_id: int,
) -> bool:
    target_type_id = int(projectile_type_id)
    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadProjectileSpawn):
            continue
        owner_id = _coerce_int_like(head.data.get("owner_id"))
        if owner_id is None:
            continue
        owner_player_index = _owner_id_to_player_index(int(owner_id), player_count=int(player_count))
        if owner_player_index is None or int(owner_player_index) != int(player_index):
            continue
        requested_type = _coerce_int_like(head.data.get("requested_type_id"))
        actual_type = _coerce_int_like(head.data.get("actual_type_id"))
        if requested_type is not None and int(requested_type) == int(target_type_id):
            return True
        if actual_type is not None and int(actual_type) == int(target_type_id):
            return True
    return False


def _should_synthesize_computer_fire_down(
    *,
    tick: CaptureTick,
    player_index: int,
    player_count: int,
    aim_scheme: int | None,
    sample: object | None,
    fire_down_raw: object | None,
    fire_pressed_raw: object | None,
    ammo_dropped_since_previous_checkpoint: bool,
    weapon_id_hint: int | None,
) -> bool:
    if aim_scheme is not None and int(aim_scheme) != int(_AIM_SCHEME_COMPUTER):
        return False
    if bool(fire_down_raw) or bool(fire_pressed_raw):
        return False

    fired_events = _coerce_int_like(getattr(sample, "fired_events", None))
    if aim_scheme is not None and int(aim_scheme) == int(_AIM_SCHEME_COMPUTER) and fired_events is not None and int(fired_events) > 0:
        return True

    player_projectile_spawn_count = _tick_player_projectile_spawn_count(
        tick,
        player_index=int(player_index),
        player_count=int(player_count),
    )
    player_secondary_spawn_count = _tick_player_secondary_projectile_spawn_count(
        tick,
        player_index=int(player_index),
        player_count=int(player_count),
    )
    player_projectile_spawned = int(player_projectile_spawn_count) > 0
    player_secondary_spawned = int(player_secondary_spawn_count) > 0
    if not player_projectile_spawned and not player_secondary_spawned:
        return False
    if bool(ammo_dropped_since_previous_checkpoint):
        return True
    if bool(player_secondary_spawned):
        return True
    if _tick_player_projectile_bonus_apply(
        tick,
        player_index=int(player_index),
        player_count=int(player_count),
    ):
        if weapon_id_hint is not None and _tick_player_weapon_projectile_spawned(
            tick,
            player_index=int(player_index),
            player_count=int(player_count),
            weapon_id=int(weapon_id_hint),
        ):
            return True
        return False
    if weapon_id_hint is None:
        return _tick_player_projectile_type_spawned(
            tick,
            player_index=int(player_index),
            player_count=int(player_count),
            projectile_type_id=int(_PROJECTILE_TYPE_FIRE_BULLETS),
        )
    if _tick_player_weapon_projectile_spawned(
        tick,
        player_index=int(player_index),
        player_count=int(player_count),
        weapon_id=int(weapon_id_hint),
    ):
        return True
    return _tick_player_projectile_type_spawned(
        tick,
        player_index=int(player_index),
        player_count=int(player_count),
        projectile_type_id=int(_PROJECTILE_TYPE_FIRE_BULLETS),
    )


def _infer_status_snapshot(capture: CaptureFile) -> ReplayStatusSnapshot:
    unlock_index = -1
    unlock_index_full = -1
    usage_counts: tuple[int, ...] = ()

    for tick in sorted(capture.ticks, key=lambda item: int(item.tick_index)):
        status = tick.checkpoint.status
        if int(unlock_index) < 0 and int(status.quest_unlock_index) >= 0:
            unlock_index = int(status.quest_unlock_index)
        if int(unlock_index_full) < 0 and int(status.quest_unlock_index_full) >= 0:
            unlock_index_full = int(status.quest_unlock_index_full)
        if not usage_counts and status.weapon_usage_counts:
            usage_counts = tuple(int(value) & 0xFFFFFFFF for value in status.weapon_usage_counts)
        if int(unlock_index) >= 0 and int(unlock_index_full) >= 0 and usage_counts:
            break

    counts = list(usage_counts[:WEAPON_USAGE_COUNT])
    if len(counts) < WEAPON_USAGE_COUNT:
        counts.extend([0] * (WEAPON_USAGE_COUNT - len(counts)))

    return ReplayStatusSnapshot(
        quest_unlock_index=max(0, int(unlock_index)),
        quest_unlock_index_full=max(0, int(unlock_index_full)),
        weapon_usage_counts=tuple(int(value) & 0xFFFFFFFF for value in counts),
    )


def _normalize_capture_move_components(move_dx: float, move_dy: float) -> tuple[float, float]:
    x = float(move_dx)
    y = float(move_dy)
    if not math.isfinite(x):
        x = 0.0
    if not math.isfinite(y):
        y = 0.0
    mag_sq = x * x + y * y
    if mag_sq > 1.0:
        mag = math.sqrt(mag_sq)
        if mag > 1e-9:
            inv = 1.0 / mag
            x *= inv
            y *= inv
    return (max(-1.0, min(1.0, x)), max(-1.0, min(1.0, y)))


def _crt_rand_step(state: int) -> tuple[int, int]:
    next_state = (int(state) * _CRT_RAND_MULT + _CRT_RAND_INC) & _CRT_RAND_MOD_MASK
    return int(next_state), int((next_state >> 16) & 0x7FFF)


def _seed_matches_rng_marks(seed: int, *, rng_head: list[int], rand_calls: object, rand_last: object) -> bool:
    if not rng_head:
        return False

    parsed_rand_calls = _coerce_int_like(rand_calls)
    parsed_rand_last = _coerce_int_like(rand_last)
    required_calls = len(rng_head)
    if parsed_rand_calls is not None and int(parsed_rand_calls) > 0:
        required_calls = max(required_calls, int(parsed_rand_calls))

    state = int(seed) & _CRT_RAND_MOD_MASK
    output_at_rand_calls: int | None = None
    for call_idx in range(1, int(required_calls) + 1):
        state, out = _crt_rand_step(state)
        if call_idx <= len(rng_head) and int(out) != int(rng_head[call_idx - 1]):
            return False
        if parsed_rand_calls is not None and int(parsed_rand_calls) > 0 and int(call_idx) == int(parsed_rand_calls):
            output_at_rand_calls = int(out)

    if parsed_rand_calls is not None and int(parsed_rand_calls) > 0 and parsed_rand_last is not None:
        if output_at_rand_calls is None:
            return False
        return int(output_at_rand_calls) == int(parsed_rand_last)

    return True


def _infer_seed_from_rng_head(*, rng_head: list[int], rand_calls: object, rand_last: object) -> int | None:
    if not rng_head:
        return None

    first_rand = int(rng_head[0])
    if first_rand < 0 or first_rand > 0x7FFF:
        return None

    best: int | None = None
    for high_word in (int(first_rand), int(first_rand) | 0x8000):
        state_prefix = int(high_word) << 16
        for state_low in range(0x10000):
            state_after_first = (int(state_prefix) | int(state_low)) & _CRT_RAND_MOD_MASK
            seed = ((int(state_after_first) - _CRT_RAND_INC) * _CRT_RAND_INV_MULT) & _CRT_RAND_MOD_MASK
            if not _seed_matches_rng_marks(
                int(seed),
                rng_head=rng_head,
                rand_calls=rand_calls,
                rand_last=rand_last,
            ):
                continue
            canonical_seed = int(seed) & 0x7FFFFFFF
            if best is None or int(canonical_seed) < int(best):
                best = int(canonical_seed)
    return best


def infer_capture_seed(capture: CaptureFile) -> int:
    for tick in sorted(capture.ticks, key=lambda item: int(item.tick_index)):
        seed_from_state = _infer_seed_from_rng_state_before(tick)
        if seed_from_state is not None:
            return int(seed_from_state)

        rng_head = _rng_head_values(tick)
        if not rng_head:
            continue
        marks = tick.checkpoint.rng_marks
        rand_calls: object = int(marks.rand_calls)
        rand_last: object = marks.rand_last
        if int(rand_calls) <= 0 and int(tick.rng.calls) > 0:
            rand_calls = int(tick.rng.calls)
        if rand_last is None:
            rand_last = tick.rng.last_value
        seed = _infer_seed_from_rng_head(
            rng_head=rng_head,
            rand_calls=rand_calls,
            rand_last=rand_last,
        )
        if seed is not None:
            return int(seed)
    return 0


def build_capture_dt_frame_overrides(capture: CaptureFile, *, tick_rate: int = 60) -> dict[int, float]:
    nominal_tick_rate = max(1, int(tick_rate))
    nominal_dt = 1.0 / float(nominal_tick_rate)
    if not capture.ticks:
        return {}

    sorted_ticks = sorted(capture.ticks, key=lambda item: int(item.tick_index))
    out: dict[int, float] = {}
    explicit_overrides: dict[int, float] = {}
    last_timed_tick: int | None = None
    last_timed_elapsed_ms: int | None = None

    for tick in sorted_ticks:
        tick_index = int(tick.tick_index)
        frame_dt_ms = _tick_frame_dt_ms(tick)
        if frame_dt_ms is not None:
            dt_frame = float(frame_dt_ms) / 1000.0
            if math.isfinite(dt_frame) and dt_frame > 0.0:
                explicit_overrides[int(tick_index)] = float(dt_frame)

        elapsed_ms = int(tick.checkpoint.elapsed_ms)
        if elapsed_ms < 0:
            continue

        if last_timed_tick is not None and last_timed_elapsed_ms is not None:
            gap = int(tick_index) - int(last_timed_tick)
            delta_ms = int(elapsed_ms) - int(last_timed_elapsed_ms)
            if gap > 0 and delta_ms > 0:
                dt_frame = float(delta_ms) / float(gap) / 1000.0
                if math.isfinite(dt_frame) and dt_frame > 0.0:
                    for step_tick in range(int(last_timed_tick) + 1, int(tick_index) + 1):
                        out[int(step_tick)] = float(dt_frame)

        last_timed_tick = int(tick_index)
        last_timed_elapsed_ms = int(elapsed_ms)

    out.update(explicit_overrides)

    for tick_index in list(out.keys()):
        if int(tick_index) in explicit_overrides:
            continue
        if math.isclose(float(out[tick_index]), float(nominal_dt), rel_tol=1e-9, abs_tol=1e-9):
            del out[tick_index]

    return out


def build_capture_dt_frame_ms_i32_overrides(capture: CaptureFile) -> dict[int, int]:
    out: dict[int, int] = {}
    for tick in capture.ticks:
        tick_index = int(tick.tick_index)
        dt_ms_i32 = _tick_frame_dt_ms_i32(tick)
        if dt_ms_i32 is None:
            continue
        dt_ms_i32 = int(dt_ms_i32)
        if dt_ms_i32 <= 0:
            continue
        out[int(tick_index)] = int(dt_ms_i32)
    return out


def build_capture_inter_tick_rand_draws_overrides(capture: CaptureFile) -> dict[int, int] | None:
    out: dict[int, int] = {}
    for tick in capture.ticks:
        outside_before_calls = getattr(tick, "rng_outside_before_calls", None)
        if outside_before_calls is None:
            outside_before_calls = tick.checkpoint.rng_marks.rand_outside_before_calls
        calls = _coerce_int_like(outside_before_calls)
        if calls is None or int(calls) < 0:
            continue
        out[int(tick.tick_index)] = int(calls)

    if out:
        first_tick_index = min(out)
        # Inferred replay seed already matches the first sampled tick state.
        out[int(first_tick_index)] = 0
        return out
    return None


def _capture_bootstrap_payload(
    tick: CaptureTick,
    *,
    digital_move_enabled_by_player: list[bool] | None = None,
) -> dict[str, object]:
    players: list[dict[str, object]] = []
    for player in tick.checkpoint.players:
        players.append(
            {
                "pos": {"x": float(player.pos.x), "y": float(player.pos.y)},
                "health": float(player.health),
                "weapon_id": int(player.weapon_id),
                "ammo": float(player.ammo),
                "experience": int(player.experience),
                "level": int(player.level),
                "bonus_timers_ms": {str(key): int(value) for key, value in player.bonus_timers.items()},
            }
        )
    return {
        "tick_index": int(tick.tick_index),
        "elapsed_ms": int(tick.checkpoint.elapsed_ms),
        "score_xp": int(tick.checkpoint.score_xp),
        "perk_pending": int(tick.checkpoint.perk_pending),
        "bonus_timers_ms": dict(tick.checkpoint.bonus_timers),
        "players": players,
        "digital_move_enabled_by_player": (
            [bool(value) for value in digital_move_enabled_by_player]
            if digital_move_enabled_by_player is not None
            else []
        ),
    }


def _event_payload_object(payload: list[object]) -> dict[str, object] | None:
    if not payload:
        return None
    try:
        return msgspec.convert(payload[0], type=dict[str, object], strict=False)
    except msgspec.ValidationError:
        return None


def capture_bootstrap_payload_from_event_payload(payload: list[object]) -> dict[str, object] | None:
    return _event_payload_object(payload)


def capture_perk_apply_id_from_event_payload(payload: list[object]) -> int | None:
    parsed = capture_perk_apply_from_event_payload(payload)
    if parsed is None:
        return None
    perk_id, _ = parsed
    return int(perk_id)


def capture_perk_apply_from_event_payload(payload: list[object]) -> tuple[int, bool] | None:
    event_payload = _event_payload_object(payload)
    if event_payload is None:
        return None
    try:
        parsed = msgspec.convert(event_payload, type=_CapturePerkApplyPayload, strict=False)
    except msgspec.ValidationError:
        return None
    return int(parsed.perk_id), bool(parsed.outside_before)


def capture_perk_pending_from_event_payload(payload: list[object]) -> int | None:
    event_payload = _event_payload_object(payload)
    if event_payload is None:
        return None
    try:
        parsed = msgspec.convert(event_payload, type=_CapturePerkPendingPayload, strict=False)
    except msgspec.ValidationError:
        return None
    return int(parsed.perk_pending)


def apply_capture_bootstrap_payload(
    payload: dict[str, object],
    *,
    state: object,
    players: list[object],
) -> int | None:
    from ..gameplay import weapon_assign_player

    elapsed_ms: int | None = None
    elapsed_raw = _coerce_int_like(payload.get("elapsed_ms"))
    if elapsed_raw is not None and int(elapsed_raw) >= 0:
        elapsed_ms = int(elapsed_raw)

    players_raw = payload.get("players")
    if isinstance(players_raw, list):
        for idx, raw_player in enumerate(players_raw):
            if idx >= len(players):
                break
            if not isinstance(raw_player, dict):
                continue
            player = players[idx]

            weapon_id = _coerce_int_like(raw_player.get("weapon_id"))  # ty:ignore[invalid-argument-type]
            if weapon_id is not None and int(weapon_id) > 0:
                try:
                    if int(getattr(player, "weapon_id", 0)) != int(weapon_id):
                        weapon_assign_player(player, int(weapon_id), state=state)  # ty:ignore[invalid-argument-type]
                except Exception:
                    pass

            pos_raw = raw_player.get("pos")  # ty:ignore[invalid-argument-type]
            if isinstance(pos_raw, dict):
                px = _float_or(pos_raw.get("x"), float(getattr(player, "pos").x))
                py = _float_or(pos_raw.get("y"), float(getattr(player, "pos").y))
                if math.isfinite(px) and math.isfinite(py):
                    setattr(player, "pos", Vec2(float(px), float(py)))

            health = _float_or(raw_player.get("health"), float(getattr(player, "health")))  # ty:ignore[invalid-argument-type]
            ammo = _float_or(raw_player.get("ammo"), float(getattr(player, "ammo")))  # ty:ignore[invalid-argument-type]
            experience = _coerce_int_like(raw_player.get("experience"))  # ty:ignore[invalid-argument-type]
            level = _coerce_int_like(raw_player.get("level"))  # ty:ignore[invalid-argument-type]

            setattr(player, "health", float(health))
            setattr(player, "ammo", float(ammo))
            if experience is not None:
                setattr(player, "experience", int(experience))
            if level is not None and int(level) > 0:
                setattr(player, "level", int(level))

            player_timers_raw = raw_player.get("bonus_timers_ms")  # ty:ignore[invalid-argument-type]
            if isinstance(player_timers_raw, dict):
                try:
                    shield_ms = _coerce_int_like(player_timers_raw.get("shield"))
                    fire_bullets_ms = _coerce_int_like(player_timers_raw.get("fire_bullets"))
                    speed_bonus_ms = _coerce_int_like(player_timers_raw.get("speed_bonus"))
                    if shield_ms is not None:
                        setattr(player, "shield_timer", max(0.0, float(shield_ms) / 1000.0))
                    if fire_bullets_ms is not None:
                        setattr(player, "fire_bullets_timer", max(0.0, float(fire_bullets_ms) / 1000.0))
                    if speed_bonus_ms is not None:
                        setattr(player, "speed_bonus_timer", max(0.0, float(speed_bonus_ms) / 1000.0))
                except Exception:
                    pass

    pending = _coerce_int_like(payload.get("perk_pending"))
    if pending is not None and int(pending) >= 0:
        try:
            state.perk_selection.pending_count = int(pending)  # ty:ignore[unresolved-attribute]
            state.perk_selection.choices_dirty = True  # ty:ignore[unresolved-attribute]
        except Exception:
            pass

    timers_raw = payload.get("bonus_timers_ms")
    if isinstance(timers_raw, dict):
        try:
            weapon_power_up_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.WEAPON_POWER_UP))))  # ty:ignore[invalid-argument-type]
            reflex_boost_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.REFLEX_BOOST))))  # ty:ignore[invalid-argument-type]
            energizer_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.ENERGIZER))))  # ty:ignore[invalid-argument-type]
            double_xp_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.DOUBLE_EXPERIENCE))))  # ty:ignore[invalid-argument-type]
            freeze_ms = _coerce_int_like(timers_raw.get(str(int(BonusId.FREEZE))))  # ty:ignore[invalid-argument-type]
            if weapon_power_up_ms is not None:
                state.bonuses.weapon_power_up = max(0.0, float(weapon_power_up_ms) / 1000.0)  # ty:ignore[unresolved-attribute]
            if reflex_boost_ms is not None:
                state.bonuses.reflex_boost = max(0.0, float(reflex_boost_ms) / 1000.0)  # ty:ignore[unresolved-attribute]
            if energizer_ms is not None:
                state.bonuses.energizer = max(0.0, float(energizer_ms) / 1000.0)  # ty:ignore[unresolved-attribute]
            if double_xp_ms is not None:
                state.bonuses.double_experience = max(0.0, float(double_xp_ms) / 1000.0)  # ty:ignore[unresolved-attribute]
            if freeze_ms is not None:
                state.bonuses.freeze = max(0.0, float(freeze_ms) / 1000.0)  # ty:ignore[unresolved-attribute]
            state.time_scale_active = float(state.bonuses.reflex_boost) > 0.0  # ty:ignore[unresolved-attribute]
        except Exception:
            pass

    return elapsed_ms


def _perk_apply_rows_in_tick(tick: CaptureTick) -> tuple[tuple[int, bool], ...]:
    out: list[tuple[int, bool]] = []

    for item in tick.perk_apply_outside_before.head:
        perk_id = item.perk_id
        if perk_id is None or int(perk_id) <= 0:
            continue
        out.append((int(perk_id), True))

    for item in tick.perk_apply_in_tick:
        perk_id = item.perk_id
        if perk_id is None or int(perk_id) <= 0:
            continue
        out.append((int(perk_id), False))

    if not tick.perk_apply_in_tick:
        for head in tick.event_heads:
            if isinstance(head, CaptureEventHeadPerkApply):
                if head.perk_id is not None and int(head.perk_id) > 0:
                    out.append((int(head.perk_id), False))

    deduped: list[tuple[int, bool]] = []
    seen: set[int] = set()
    for perk_id, outside_before in out:
        if int(perk_id) in seen:
            continue
        seen.add(int(perk_id))
        deduped.append((int(perk_id), bool(outside_before)))
    return tuple(deduped)


def _tick_perk_pending_count(tick: CaptureTick) -> int | None:
    pending = int(tick.checkpoint.perk_pending)
    if pending >= 0:
        return int(pending)

    snapshot_pending = int(tick.checkpoint.perk.pending_count)
    if snapshot_pending >= 0:
        return int(snapshot_pending)

    for head in tick.event_heads:
        if not isinstance(head, CaptureEventHeadPerkDelta):
            continue
        pending_value = _coerce_int_like(head.data.get("perk_pending_count"))
        if pending_value is not None and int(pending_value) >= 0:
            return int(pending_value)
    return None


def convert_capture_to_checkpoints(capture: CaptureFile, *, replay_sha256: str = "") -> ReplayCheckpoints:
    checkpoints: list[ReplayCheckpoint] = []
    for tick in capture.ticks:
        ckpt = tick.checkpoint
        checkpoints.append(
            ReplayCheckpoint(
                tick_index=int(tick.tick_index),
                rng_state=int(ckpt.rng_state),
                elapsed_ms=int(ckpt.elapsed_ms),
                score_xp=int(ckpt.score_xp),
                kills=int(ckpt.kills),
                creature_count=int(ckpt.creature_count),
                perk_pending=int(ckpt.perk_pending),
                players=[_replay_player(player) for player in ckpt.players],
                bonus_timers={str(key): int(value) for key, value in ckpt.bonus_timers.items()},
                state_hash=str(ckpt.state_hash),
                command_hash=str(ckpt.command_hash),
                rng_marks=_rng_marks_int_map(tick),
                deaths=[_replay_death(item) for item in ckpt.deaths],
                perk=_replay_perk(ckpt.perk),
                events=_replay_events(ckpt.events),
            )
        )

    return ReplayCheckpoints(
        version=FORMAT_VERSION,
        replay_sha256=str(replay_sha256),
        sample_rate=_capture_sample_rate(capture),
        checkpoints=checkpoints,
    )


def convert_capture_to_replay(
    capture: CaptureFile,
    *,
    seed: int | None = None,
    tick_rate: int = 60,
    world_size: float = 1024.0,
    game_mode_id: int | None = None,
    aim_scheme_overrides_by_player: Mapping[int, int] | None = None,
) -> Replay:
    resolved_seed = infer_capture_seed(capture) if seed is None else int(seed)
    player_count = _infer_player_count(capture)
    digital_move_enabled_by_player = _infer_digital_move_enabled_by_player(
        capture,
        player_count=int(player_count),
    )
    resolved_mode_id = _infer_game_mode_id(capture) if game_mode_id is None else int(game_mode_id)
    status_snapshot = _infer_status_snapshot(capture)

    if capture.ticks:
        max_tick_index = max(max(0, int(tick.tick_index)) for tick in capture.ticks)
        total_ticks = int(max_tick_index) + 1
    else:
        total_ticks = 0

    inputs: list[list[list[float | int | list[float]]]] = [
        [[0.0, 0.0, [0.0, 0.0], 0] for _ in range(player_count)] for _ in range(total_ticks)
    ]
    previous_checkpoint_ammo: list[float | None] = [None for _ in range(player_count)]
    normalized_aim_scheme_overrides = dict(aim_scheme_overrides_by_player or {})

    for tick in sorted(capture.ticks, key=lambda item: int(item.tick_index)):
        tick_index = int(tick.tick_index)
        if tick_index < 0 or tick_index >= total_ticks:
            continue
        approx_by_player = {int(sample.player_index): sample for sample in tick.input_approx}
        keys_by_player = {int(row.player_index): row for row in tick.input_player_keys}
        checkpoint_players = tick.checkpoint.players
        for player_index in range(player_count):
            sample = approx_by_player.get(int(player_index))
            key_row = keys_by_player.get(int(player_index))
            if normalized_aim_scheme_overrides:
                aim_scheme_value = _coerce_player_int(
                    normalized_aim_scheme_overrides,
                    player_index=int(player_index),
                )
            else:
                aim_scheme_value = None
            if aim_scheme_value is None:
                aim_scheme_value = _tick_player_aim_scheme(tick, player_index=int(player_index))
            fire_down_raw = None
            fire_pressed_raw = None
            reload_pressed_raw = None
            use_digital_move = False
            ammo_dropped_since_previous_checkpoint = False

            checkpoint_ammo: float | None = None
            weapon_id_hint: int | None = None
            if 0 <= int(player_index) < len(checkpoint_players):
                checkpoint_ammo = float(checkpoint_players[int(player_index)].ammo)
                weapon_id_hint = int(checkpoint_players[int(player_index)].weapon_id)
                previous_ammo = previous_checkpoint_ammo[int(player_index)]
                if previous_ammo is not None and float(checkpoint_ammo) < float(previous_ammo) - 1e-6:
                    ammo_dropped_since_previous_checkpoint = True
            sample_weapon_id = _coerce_int_like(getattr(sample, "weapon_id", None))
            if sample_weapon_id is not None:
                weapon_id_hint = int(sample_weapon_id)

            if sample is not None or key_row is not None:
                move_forward_raw = key_row.move_forward_pressed if key_row is not None else None
                move_backward_raw = key_row.move_backward_pressed if key_row is not None else None
                turn_left_raw = key_row.turn_left_pressed if key_row is not None else None
                turn_right_raw = key_row.turn_right_pressed if key_row is not None else None
                sample_move_dx = float(sample.move_dx) if sample is not None else 0.0
                sample_move_dy = float(sample.move_dy) if sample is not None else 0.0
                has_digital_move = (
                    move_forward_raw is not None
                    or move_backward_raw is not None
                    or turn_left_raw is not None
                    or turn_right_raw is not None
                )
                use_digital_move = bool(
                    has_digital_move
                    and 0 <= int(player_index) < len(digital_move_enabled_by_player)
                    and bool(digital_move_enabled_by_player[int(player_index)])
                )
                if use_digital_move:
                    turn_left = bool(turn_left_raw)
                    turn_right = bool(turn_right_raw)
                    move_forward = bool(move_forward_raw)
                    move_backward = bool(move_backward_raw)
                    move_x = float(turn_right) - float(turn_left)
                    move_y = float(move_backward) - float(move_forward)
                    if turn_left and turn_right:
                        # `input_player_keys` collapses multiple key-query sites in
                        # `player_update`. When move forward/backward is also active,
                        # a later branch can override turn intent with left-biased
                        # precedence; without move keys the initial turn branch stays
                        # right-biased.
                        move_x = -1.0 if (move_forward or move_backward) else 1.0
                    if move_forward and move_backward:
                        # Same collapse behavior for move intent: with turn keys in
                        # play, the later branch can resolve toward forward.
                        move_y = -1.0 if (turn_left or turn_right) else 1.0
                else:
                    move_x, move_y = _normalize_capture_move_components(sample_move_dx, sample_move_dy)

                if sample is not None:
                    aim_x_raw = float(sample.aim_x)
                    aim_y_raw = float(sample.aim_y)
                    has_aim_xy = math.isfinite(aim_x_raw) and math.isfinite(aim_y_raw)
                    use_heading_fallback = (
                        (not has_aim_xy or (aim_x_raw == 0.0 and aim_y_raw == 0.0))
                        and sample.aim_heading is not None
                    )
                else:
                    aim_x_raw = 0.0
                    aim_y_raw = 0.0
                    has_aim_xy = False
                    use_heading_fallback = False

                if use_heading_fallback:
                    if sample is None or sample.aim_heading is None:
                        continue
                    players = tick.checkpoint.players
                    if player_index < len(players):
                        player_pos_capture = players[player_index].pos
                        player_pos = Vec2(float(player_pos_capture.x), float(player_pos_capture.y))
                    else:
                        player_pos = Vec2()
                    aim_pos = player_pos + Vec2.from_heading(float(sample.aim_heading)) * 256.0
                    aim_x = float(aim_pos.x)
                    aim_y = float(aim_pos.y)
                elif has_aim_xy:
                    aim_x = float(aim_x_raw)
                    aim_y = float(aim_y_raw)
                else:
                    players = tick.checkpoint.players
                    if player_index < len(players):
                        player = players[player_index]
                        aim_x = float(player.pos.x)
                        aim_y = float(player.pos.y)
                    else:
                        aim_x = 0.0
                        aim_y = 0.0

                if key_row is not None:
                    fire_down_raw = key_row.fire_down
                    fire_pressed_raw = key_row.fire_pressed
                    reload_pressed_raw = key_row.reload_pressed

                fire_down = bool(fire_down_raw) if fire_down_raw is not None else False
                fire_pressed = bool(fire_pressed_raw) if fire_pressed_raw is not None else False
                reload_pressed = bool(reload_pressed_raw) if reload_pressed_raw is not None else False
            else:
                move_x = 0.0
                move_y = 0.0
                players = tick.checkpoint.players
                if player_index < len(players):
                    player = players[player_index]
                    aim_x = float(player.pos.x)
                    aim_y = float(player.pos.y)
                else:
                    aim_x = 0.0
                    aim_y = 0.0
                fire_pressed = False
                fire_down = False
                reload_pressed = False
                fire_down_raw = None
                fire_pressed_raw = None
                reload_pressed_raw = None

            if _should_synthesize_computer_fire_down(
                tick=tick,
                player_index=int(player_index),
                player_count=int(player_count),
                aim_scheme=aim_scheme_value,
                sample=sample,
                fire_down_raw=fire_down_raw,
                fire_pressed_raw=fire_pressed_raw,
                ammo_dropped_since_previous_checkpoint=ammo_dropped_since_previous_checkpoint,
                weapon_id_hint=weapon_id_hint,
            ):
                fire_down = True

            flags = pack_input_flags(
                fire_down=bool(fire_down),
                fire_pressed=bool(fire_pressed),
                reload_pressed=bool(reload_pressed),
            )
            inputs[tick_index][player_index] = [float(move_x), float(move_y), [float(aim_x), float(aim_y)], int(flags)]
            if checkpoint_ammo is not None:
                previous_checkpoint_ammo[int(player_index)] = float(checkpoint_ammo)

    events: list[object] = []
    if capture.ticks:
        first_tick = min(capture.ticks, key=lambda item: int(item.tick_index))
        bootstrap_tick = max(0, int(first_tick.tick_index))
        events.append(
            UnknownEvent(
                tick_index=int(bootstrap_tick),
                kind=CAPTURE_BOOTSTRAP_EVENT_KIND,
                payload=[
                    _capture_bootstrap_payload(
                        first_tick,
                        digital_move_enabled_by_player=digital_move_enabled_by_player,
                    )
                ],
            )
        )

        sorted_ticks = sorted(capture.ticks, key=lambda item: int(item.tick_index))
        previous_pending: int | None = None
        for tick in sorted_ticks:
            captured_perk_apply_rows = list(_perk_apply_rows_in_tick(tick))
            if captured_perk_apply_rows:
                seen_perk_apply_ids: set[int] = set()
                for perk_id, outside_before in captured_perk_apply_rows:
                    if int(perk_id) <= 0 or int(perk_id) in seen_perk_apply_ids:
                        continue
                    seen_perk_apply_ids.add(int(perk_id))
                    events.append(
                        UnknownEvent(
                            tick_index=int(tick.tick_index),
                            kind=CAPTURE_PERK_APPLY_EVENT_KIND,
                            payload=[{"perk_id": int(perk_id), "outside_before": bool(outside_before)}],
                        )
                    )

            pending = _tick_perk_pending_count(tick)
            if pending is None:
                continue
            pending_i = int(pending)
            if previous_pending is not None and pending_i < previous_pending:
                menu_tick = max(0, int(tick.tick_index) - 1)
                events.append(
                    UnknownEvent(
                        tick_index=int(menu_tick),
                        kind=CAPTURE_PERK_PENDING_EVENT_KIND,
                        payload=[{"perk_pending": int(previous_pending)}],
                    )
                )
                events.append(PerkMenuOpenEvent(tick_index=int(menu_tick), player_index=0))
                events.append(
                    UnknownEvent(
                        tick_index=int(tick.tick_index),
                        kind=CAPTURE_PERK_PENDING_EVENT_KIND,
                        payload=[{"perk_pending": int(pending_i)}],
                    )
                )
            previous_pending = int(pending_i)

    return Replay(
        version=FORMAT_VERSION,
        header=ReplayHeader(
            game_mode_id=int(resolved_mode_id),
            seed=int(resolved_seed),
            tick_rate=max(1, int(tick_rate)),
            player_count=int(player_count),
            preserve_bugs=True,
            world_size=float(world_size),
            status=status_snapshot,
        ),
        inputs=inputs,
        events=list(events),  # ty:ignore[invalid-argument-type]
    )


def default_capture_replay_path(checkpoints_path: Path) -> Path:
    checkpoints_path = Path(checkpoints_path)
    name = checkpoints_path.name
    if name.endswith(".checkpoints.json.gz"):
        stem = name[: -len(".checkpoints.json.gz")]
    elif name.endswith(".json.gz"):
        stem = name[: -len(".json.gz")]
    elif name.endswith(".json"):
        stem = name[: -len(".json")]
    else:
        stem = name
    return checkpoints_path.with_name(f"{stem}.crdemo.gz")


def _validate_capture_path(path: Path) -> None:
    lower = str(path).lower()
    if lower.endswith(".json") or lower.endswith(".json.gz"):
        return
    raise CaptureError(f"capture path must end with .json or .json.gz: {path}")


def _validate_capture_format_version(capture: CaptureFile, path: Path) -> None:
    version = int(capture.capture_format_version)
    if int(version) == int(CAPTURE_FORMAT_VERSION):
        return
    raise CaptureError(
        "unsupported capture format version for "
        f"{path}: got {version}, expected {int(CAPTURE_FORMAT_VERSION)}"
    )


def _decode_capture_stream(raw: bytes, path: Path) -> CaptureFile | None:
    lines = raw.splitlines()
    if not lines:
        return None

    meta: CaptureFile | None = None
    ticks: list[CaptureTick] = []
    saw_stream_row = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        try:
            row_obj = msgspec.json.decode(line)
            row_obj = _decode_f32_tokens(row_obj)
            row = msgspec.convert(row_obj, type=_CaptureStreamRow, strict=False)
        except (msgspec.DecodeError, msgspec.ValidationError) as exc:
            raise CaptureError(f"invalid capture file: {path}") from exc

        if isinstance(row, _CaptureStreamMetaRow):
            meta = row.capture
            saw_stream_row = True
            continue

        if isinstance(row, _CaptureStreamTickRow):
            ticks.append(row.tick)
            saw_stream_row = True
            continue

    if not saw_stream_row or meta is None:
        return None

    meta.ticks = ticks
    return meta


def load_capture(path: Path) -> CaptureFile:
    path = Path(path)
    _validate_capture_path(path)

    raw = path.read_bytes()
    if raw.startswith(b"\x1f\x8b"):
        raw = gzip.decompress(raw)

    stream = _decode_capture_stream(raw, path)
    if stream is not None:
        _validate_capture_format_version(stream, path)
        return stream

    raise CaptureError(f"invalid capture file: {path}")


def dump_capture(path: Path, capture: CaptureFile) -> None:
    path = Path(path)
    _validate_capture_path(path)
    _validate_capture_format_version(capture, path)
    capture_obj = msgspec.to_builtins(capture)
    if not isinstance(capture_obj, dict):
        raise CaptureError("invalid capture object during serialization")
    ticks_obj = capture_obj.get("ticks")
    ticks = ticks_obj if isinstance(ticks_obj, list) else []
    meta = dict(capture_obj)
    meta["ticks"] = []
    rows: list[bytes] = [msgspec.json.encode({"event": "capture_meta", "capture": meta})]
    rows.extend(msgspec.json.encode({"event": "tick", "tick": tick}) for tick in ticks)
    encoded = b"\n".join(rows) + b"\n"
    if str(path).lower().endswith(".gz"):
        path.write_bytes(gzip.compress(encoded))
    else:
        path.write_bytes(encoded)
