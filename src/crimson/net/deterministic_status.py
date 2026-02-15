from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
from typing import SupportsInt, cast

from ..persistence.save_status import (
    QUEST_PLAY_COUNT,
    UNKNOWN_TAIL_SIZE,
    WEAPON_USAGE_COUNT,
    GameStatus,
    build_status_blob,
)

from .protocol import StatusSnapshot


def status_snapshot_from_status(status: GameStatus | None) -> StatusSnapshot:
    if status is None:
        return StatusSnapshot()

    def _mask_u32(value: object) -> int:
        try:
            return int(cast(SupportsInt, value)) & 0xFFFFFFFF
        except (TypeError, ValueError, OverflowError):
            return 0

    def _take_u32_list(raw: object, *, size: int) -> list[int]:
        if not isinstance(raw, list):
            return [0] * int(size)
        out: list[int] = []
        for value in raw[: int(size)]:
            out.append(_mask_u32(value))
        if len(out) < int(size):
            out.extend([0] * (int(size) - len(out)))
        return out

    data = getattr(status, "data", {}) or {}
    tail = data.get("unknown_tail", b"")
    if not isinstance(tail, (bytes, bytearray)):
        tail = b""
    tail = bytes(tail)
    if len(tail) != int(UNKNOWN_TAIL_SIZE):
        tail = tail[: int(UNKNOWN_TAIL_SIZE)] + (b"\x00" * max(0, int(UNKNOWN_TAIL_SIZE) - len(tail)))

    return StatusSnapshot(
        quest_unlock_index=int(data.get("quest_unlock_index", 0) or 0) & 0xFFFF,
        quest_unlock_index_full=int(data.get("quest_unlock_index_full", 0) or 0) & 0xFFFF,
        weapon_usage_counts=_take_u32_list(data.get("weapon_usage_counts"), size=int(WEAPON_USAGE_COUNT)),
        quest_play_counts=_take_u32_list(data.get("quest_play_counts"), size=int(QUEST_PLAY_COUNT)),
        mode_play_survival=_mask_u32(data.get("mode_play_survival", 0)),
        mode_play_rush=_mask_u32(data.get("mode_play_rush", 0)),
        mode_play_typo=_mask_u32(data.get("mode_play_typo", 0)),
        mode_play_other=_mask_u32(data.get("mode_play_other", 0)),
        game_sequence_id=_mask_u32(data.get("game_sequence_id", 0)),
        unknown_tail=tail,
    )


def hash_status_snapshot(snapshot: StatusSnapshot) -> str:
    """Stable hash for sanity-checking host/client status snapshots."""

    data = {
        "quest_unlock_index": int(getattr(snapshot, "quest_unlock_index", 0) or 0) & 0xFFFF,
        "quest_unlock_index_full": int(getattr(snapshot, "quest_unlock_index_full", 0) or 0) & 0xFFFF,
        "weapon_usage_counts": list(getattr(snapshot, "weapon_usage_counts", []) or []),
        "quest_play_counts": list(getattr(snapshot, "quest_play_counts", []) or []),
        "mode_play_survival": int(getattr(snapshot, "mode_play_survival", 0) or 0) & 0xFFFFFFFF,
        "mode_play_rush": int(getattr(snapshot, "mode_play_rush", 0) or 0) & 0xFFFFFFFF,
        "mode_play_typo": int(getattr(snapshot, "mode_play_typo", 0) or 0) & 0xFFFFFFFF,
        "mode_play_other": int(getattr(snapshot, "mode_play_other", 0) or 0) & 0xFFFFFFFF,
        "game_sequence_id": int(getattr(snapshot, "game_sequence_id", 0) or 0) & 0xFFFFFFFF,
        "unknown_tail": bytes(getattr(snapshot, "unknown_tail", b"") or b""),
    }

    weapon_counts = data["weapon_usage_counts"]
    if len(weapon_counts) != int(WEAPON_USAGE_COUNT):
        weapon_counts = weapon_counts[: int(WEAPON_USAGE_COUNT)] + [0] * max(0, int(WEAPON_USAGE_COUNT) - len(weapon_counts))
        data["weapon_usage_counts"] = weapon_counts[: int(WEAPON_USAGE_COUNT)]
    quest_counts = data["quest_play_counts"]
    if len(quest_counts) != int(QUEST_PLAY_COUNT):
        quest_counts = quest_counts[: int(QUEST_PLAY_COUNT)] + [0] * max(0, int(QUEST_PLAY_COUNT) - len(quest_counts))
        data["quest_play_counts"] = quest_counts[: int(QUEST_PLAY_COUNT)]

    tail = data["unknown_tail"]
    if len(tail) != int(UNKNOWN_TAIL_SIZE):
        tail = tail[: int(UNKNOWN_TAIL_SIZE)] + (b"\x00" * max(0, int(UNKNOWN_TAIL_SIZE) - len(tail)))
        data["unknown_tail"] = tail[: int(UNKNOWN_TAIL_SIZE)]

    digest = hashlib.sha256(build_status_blob(data)).hexdigest()
    return str(digest)


def build_lan_deterministic_status(*, snapshot: StatusSnapshot | None = None) -> GameStatus:
    """Return a session-local `GameStatus` for deterministic LAN simulation.

    The host sends its save snapshot in `MatchStart`, and all peers use it as the
    simulation status. This avoids split brain where local save progress impacts
    deterministic simulation (weapon availability / RNG consumption).
    """

    # This status object should never overwrite the on-disk save. Give it a
    # safe temp path so accidental `save_if_dirty()` calls don't clobber
    # `game.cfg`.
    path = Path(tempfile.gettempdir()) / "crimson-lan-sim-game.cfg"
    snap = snapshot or StatusSnapshot()
    weapon_counts = list(getattr(snap, "weapon_usage_counts", []) or [])
    if len(weapon_counts) != int(WEAPON_USAGE_COUNT):
        weapon_counts = weapon_counts[: int(WEAPON_USAGE_COUNT)] + [0] * max(0, int(WEAPON_USAGE_COUNT) - len(weapon_counts))
        weapon_counts = weapon_counts[: int(WEAPON_USAGE_COUNT)]
    quest_counts = list(getattr(snap, "quest_play_counts", []) or [])
    if len(quest_counts) != int(QUEST_PLAY_COUNT):
        quest_counts = quest_counts[: int(QUEST_PLAY_COUNT)] + [0] * max(0, int(QUEST_PLAY_COUNT) - len(quest_counts))
        quest_counts = quest_counts[: int(QUEST_PLAY_COUNT)]
    tail = bytes(getattr(snap, "unknown_tail", b"") or b"")
    if len(tail) != int(UNKNOWN_TAIL_SIZE):
        tail = tail[: int(UNKNOWN_TAIL_SIZE)] + (b"\x00" * max(0, int(UNKNOWN_TAIL_SIZE) - len(tail)))
        tail = tail[: int(UNKNOWN_TAIL_SIZE)]

    data = {
        "quest_unlock_index": int(getattr(snap, "quest_unlock_index", 0) or 0) & 0xFFFF,
        "quest_unlock_index_full": int(getattr(snap, "quest_unlock_index_full", 0) or 0) & 0xFFFF,
        "weapon_usage_counts": weapon_counts,
        "quest_play_counts": quest_counts,
        "mode_play_survival": int(getattr(snap, "mode_play_survival", 0) or 0) & 0xFFFFFFFF,
        "mode_play_rush": int(getattr(snap, "mode_play_rush", 0) or 0) & 0xFFFFFFFF,
        "mode_play_typo": int(getattr(snap, "mode_play_typo", 0) or 0) & 0xFFFFFFFF,
        "mode_play_other": int(getattr(snap, "mode_play_other", 0) or 0) & 0xFFFFFFFF,
        "game_sequence_id": int(getattr(snap, "game_sequence_id", 0) or 0) & 0xFFFFFFFF,
        "unknown_tail": tail,
    }
    return GameStatus(path=path, data=data, dirty=False)
