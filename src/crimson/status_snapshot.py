from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, SupportsInt, cast

import msgspec

from .persistence.save_status import (
    QUEST_PLAY_COUNT,
    UNKNOWN_TAIL_SIZE,
    WEAPON_USAGE_COUNT,
    GameStatus,
    build_status_blob,
    default_status_data,
)
from .replay.types import ReplayStatusSnapshot

if TYPE_CHECKING:
    from .dbg.canonical_channels import SnapshotStatus
    from .net.lockstep_protocol import StatusSnapshot

_ZERO_WEAPON_USAGE_COUNTS: tuple[int, ...] = tuple(0 for _ in range(int(WEAPON_USAGE_COUNT)))
_ZERO_QUEST_PLAY_COUNTS: tuple[int, ...] = tuple(0 for _ in range(int(QUEST_PLAY_COUNT)))
_ZERO_UNKNOWN_TAIL = b"\x00" * int(UNKNOWN_TAIL_SIZE)


class ProgressStatusSnapshot(msgspec.Struct, frozen=True):
    quest_unlock_index: int = 0
    quest_unlock_index_full: int = 0
    weapon_usage_counts: tuple[int, ...] = msgspec.field(default_factory=lambda: _ZERO_WEAPON_USAGE_COUNTS)
    quest_play_counts: tuple[int, ...] = msgspec.field(default_factory=lambda: _ZERO_QUEST_PLAY_COUNTS)
    mode_play_survival: int = 0
    mode_play_rush: int = 0
    mode_play_typo: int = 0
    mode_play_other: int = 0
    game_sequence_id: int = 0
    unknown_tail: bytes = _ZERO_UNKNOWN_TAIL


def _mask_u16(value: object) -> int:
    try:
        return int(cast(SupportsInt, value)) & 0xFFFF
    except (TypeError, ValueError, OverflowError):
        return 0


def _mask_u32(value: object) -> int:
    try:
        return int(cast(SupportsInt, value)) & 0xFFFFFFFF
    except (TypeError, ValueError, OverflowError):
        return 0


def _normalize_u32_seq(raw: object, *, size: int) -> tuple[int, ...]:
    expected = int(size)
    if not isinstance(raw, (list, tuple)):
        return tuple(0 for _ in range(expected))
    values = [int(_mask_u32(value)) for value in list(raw)[:expected]]
    if len(values) < expected:
        values.extend([0] * (expected - len(values)))
    return tuple(values[:expected])


def _normalize_unknown_tail(raw: object) -> bytes:
    if not isinstance(raw, (bytes, bytearray)):
        return _ZERO_UNKNOWN_TAIL
    tail = bytes(raw)
    expected = int(UNKNOWN_TAIL_SIZE)
    if len(tail) < expected:
        tail = tail + (b"\x00" * (expected - len(tail)))
    return tail[:expected]


def _status_blob_data(snapshot: ProgressStatusSnapshot) -> dict[str, object]:
    return {
        "quest_unlock_index": int(snapshot.quest_unlock_index) & 0xFFFF,
        "quest_unlock_index_full": int(snapshot.quest_unlock_index_full) & 0xFFFF,
        "weapon_usage_counts": list(snapshot.weapon_usage_counts),
        "quest_play_counts": list(snapshot.quest_play_counts),
        "mode_play_survival": int(snapshot.mode_play_survival) & 0xFFFFFFFF,
        "mode_play_rush": int(snapshot.mode_play_rush) & 0xFFFFFFFF,
        "mode_play_typo": int(snapshot.mode_play_typo) & 0xFFFFFFFF,
        "mode_play_other": int(snapshot.mode_play_other) & 0xFFFFFFFF,
        "game_sequence_id": int(snapshot.game_sequence_id) & 0xFFFFFFFF,
        "unknown_tail": bytes(snapshot.unknown_tail),
    }


def progress_status_from_game_status(status: GameStatus | None) -> ProgressStatusSnapshot:
    data = {} if status is None else status.data
    return ProgressStatusSnapshot(
        quest_unlock_index=_mask_u16(data.get("quest_unlock_index", 0)),
        quest_unlock_index_full=_mask_u16(data.get("quest_unlock_index_full", 0)),
        weapon_usage_counts=_normalize_u32_seq(data.get("weapon_usage_counts"), size=int(WEAPON_USAGE_COUNT)),
        quest_play_counts=_normalize_u32_seq(data.get("quest_play_counts"), size=int(QUEST_PLAY_COUNT)),
        mode_play_survival=_mask_u32(data.get("mode_play_survival", 0)),
        mode_play_rush=_mask_u32(data.get("mode_play_rush", 0)),
        mode_play_typo=_mask_u32(data.get("mode_play_typo", 0)),
        mode_play_other=_mask_u32(data.get("mode_play_other", 0)),
        game_sequence_id=_mask_u32(data.get("game_sequence_id", 0)),
        unknown_tail=_normalize_unknown_tail(data.get("unknown_tail")),
    )


def game_status_from_progress_status(snapshot: ProgressStatusSnapshot, *, path: Path) -> GameStatus:
    data = default_status_data()
    data.update(_status_blob_data(snapshot))
    return GameStatus(path=path, data=data, dirty=False)


def game_status_from_replay_status(snapshot: ReplayStatusSnapshot | None, *, path: Path) -> GameStatus:
    return game_status_from_progress_status(
        progress_status_from_replay(snapshot),
        path=path,
    )


def progress_status_from_lockstep(snapshot: StatusSnapshot | None) -> ProgressStatusSnapshot:
    if snapshot is None:
        return ProgressStatusSnapshot()
    return ProgressStatusSnapshot(
        quest_unlock_index=_mask_u16(snapshot.quest_unlock_index),
        quest_unlock_index_full=_mask_u16(snapshot.quest_unlock_index_full),
        weapon_usage_counts=_normalize_u32_seq(snapshot.weapon_usage_counts, size=int(WEAPON_USAGE_COUNT)),
        quest_play_counts=_normalize_u32_seq(snapshot.quest_play_counts, size=int(QUEST_PLAY_COUNT)),
        mode_play_survival=_mask_u32(snapshot.mode_play_survival),
        mode_play_rush=_mask_u32(snapshot.mode_play_rush),
        mode_play_typo=_mask_u32(snapshot.mode_play_typo),
        mode_play_other=_mask_u32(snapshot.mode_play_other),
        game_sequence_id=_mask_u32(snapshot.game_sequence_id),
        unknown_tail=_normalize_unknown_tail(snapshot.unknown_tail),
    )


def lockstep_status_from_progress(snapshot: ProgressStatusSnapshot) -> StatusSnapshot:
    from .net.lockstep_protocol import StatusSnapshot

    return StatusSnapshot(
        quest_unlock_index=int(snapshot.quest_unlock_index) & 0xFFFF,
        quest_unlock_index_full=int(snapshot.quest_unlock_index_full) & 0xFFFF,
        weapon_usage_counts=list(snapshot.weapon_usage_counts),
        quest_play_counts=list(snapshot.quest_play_counts),
        mode_play_survival=int(snapshot.mode_play_survival) & 0xFFFFFFFF,
        mode_play_rush=int(snapshot.mode_play_rush) & 0xFFFFFFFF,
        mode_play_typo=int(snapshot.mode_play_typo) & 0xFFFFFFFF,
        mode_play_other=int(snapshot.mode_play_other) & 0xFFFFFFFF,
        game_sequence_id=int(snapshot.game_sequence_id) & 0xFFFFFFFF,
        unknown_tail=bytes(snapshot.unknown_tail),
    )


def progress_status_from_replay(snapshot: ReplayStatusSnapshot | None) -> ProgressStatusSnapshot:
    if snapshot is None:
        return ProgressStatusSnapshot()
    return ProgressStatusSnapshot(
        quest_unlock_index=_mask_u16(snapshot.quest_unlock_index),
        quest_unlock_index_full=_mask_u16(snapshot.quest_unlock_index_full),
        weapon_usage_counts=_normalize_u32_seq(snapshot.weapon_usage_counts, size=int(WEAPON_USAGE_COUNT)),
    )


def replay_status_from_progress(snapshot: ProgressStatusSnapshot) -> ReplayStatusSnapshot:
    return ReplayStatusSnapshot(
        quest_unlock_index=int(snapshot.quest_unlock_index) & 0xFFFF,
        quest_unlock_index_full=int(snapshot.quest_unlock_index_full) & 0xFFFF,
        weapon_usage_counts=tuple(snapshot.weapon_usage_counts),
    )


def progress_status_from_debug_snapshot(snapshot: SnapshotStatus | None) -> ProgressStatusSnapshot:
    if snapshot is None:
        return ProgressStatusSnapshot()
    return ProgressStatusSnapshot(
        quest_unlock_index=_mask_u16(snapshot.quest_unlock_index),
        quest_unlock_index_full=_mask_u16(snapshot.quest_unlock_index_full),
        weapon_usage_counts=_normalize_u32_seq(snapshot.weapon_usage_counts, size=int(WEAPON_USAGE_COUNT)),
    )


def debug_snapshot_from_progress_status(snapshot: ProgressStatusSnapshot) -> SnapshotStatus:
    from .dbg.canonical_channels import SnapshotStatus

    return SnapshotStatus(
        quest_unlock_index=int(snapshot.quest_unlock_index) & 0xFFFF,
        quest_unlock_index_full=int(snapshot.quest_unlock_index_full) & 0xFFFF,
        weapon_usage_counts=list(snapshot.weapon_usage_counts),
    )


def hash_progress_status(snapshot: ProgressStatusSnapshot) -> str:
    return hashlib.sha256(build_status_blob(_status_blob_data(snapshot))).hexdigest()
