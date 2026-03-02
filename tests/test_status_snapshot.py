from __future__ import annotations

from pathlib import Path

from crimson.dbg.canonical_channels import SnapshotStatus
from crimson.net.deterministic_status import hash_status_snapshot
from crimson.persistence.save_status import QUEST_PLAY_COUNT, UNKNOWN_TAIL_SIZE, WEAPON_USAGE_COUNT, GameStatus
from crimson.status_snapshot import (
    ProgressStatusSnapshot,
    debug_snapshot_from_progress_status,
    game_status_from_progress_status,
    hash_progress_status,
    lockstep_status_from_progress,
    progress_status_from_debug_snapshot,
    progress_status_from_game_status,
    progress_status_from_lockstep,
    progress_status_from_replay,
    replay_status_from_progress,
)


def test_progress_status_from_game_status_normalizes_and_masks() -> None:
    status = GameStatus(
        path=Path("game.cfg"),
        data={
            "quest_unlock_index": -1,
            "quest_unlock_index_full": 70000,
            "weapon_usage_counts": [1, -2, 1 << 36],
            "quest_play_counts": [5, -3],
            "mode_play_survival": -7,
            "mode_play_rush": 9,
            "mode_play_typo": 11,
            "mode_play_other": 13,
            "game_sequence_id": -1,
            "unknown_tail": b"\xAA\xBB",
        },
        dirty=False,
    )
    snapshot = progress_status_from_game_status(status)

    assert snapshot.quest_unlock_index == 0xFFFF
    assert snapshot.quest_unlock_index_full == (70000 & 0xFFFF)
    assert len(snapshot.weapon_usage_counts) == int(WEAPON_USAGE_COUNT)
    assert snapshot.weapon_usage_counts[0] == 1
    assert snapshot.weapon_usage_counts[1] == 0xFFFFFFFF - 1
    assert snapshot.weapon_usage_counts[2] == ((1 << 36) & 0xFFFFFFFF)
    assert len(snapshot.quest_play_counts) == int(QUEST_PLAY_COUNT)
    assert snapshot.quest_play_counts[0] == 5
    assert snapshot.quest_play_counts[1] == 0xFFFFFFFF - 2
    assert snapshot.mode_play_survival == 0xFFFFFFFF - 6
    assert snapshot.game_sequence_id == 0xFFFFFFFF
    assert len(snapshot.unknown_tail) == int(UNKNOWN_TAIL_SIZE)
    assert snapshot.unknown_tail[:2] == b"\xAA\xBB"


def test_lockstep_progress_roundtrip_preserves_full_payload() -> None:
    snapshot = ProgressStatusSnapshot(
        quest_unlock_index=12,
        quest_unlock_index_full=34,
        weapon_usage_counts=tuple(range(int(WEAPON_USAGE_COUNT))),
        quest_play_counts=tuple(range(int(QUEST_PLAY_COUNT))),
        mode_play_survival=101,
        mode_play_rush=102,
        mode_play_typo=103,
        mode_play_other=104,
        game_sequence_id=999,
        unknown_tail=bytes(range(int(UNKNOWN_TAIL_SIZE))),
    )

    wire = lockstep_status_from_progress(snapshot)
    restored = progress_status_from_lockstep(wire)
    assert restored == snapshot


def test_replay_progress_adapter_drops_non_replay_fields() -> None:
    snapshot = ProgressStatusSnapshot(
        quest_unlock_index=3,
        quest_unlock_index_full=7,
        weapon_usage_counts=tuple([5] * int(WEAPON_USAGE_COUNT)),
        quest_play_counts=tuple([9] * int(QUEST_PLAY_COUNT)),
        mode_play_survival=1,
        mode_play_rush=2,
        mode_play_typo=3,
        mode_play_other=4,
        game_sequence_id=55,
        unknown_tail=b"\xCD" * int(UNKNOWN_TAIL_SIZE),
    )
    replay = replay_status_from_progress(snapshot)
    restored = progress_status_from_replay(replay)

    assert restored.quest_unlock_index == snapshot.quest_unlock_index
    assert restored.quest_unlock_index_full == snapshot.quest_unlock_index_full
    assert restored.weapon_usage_counts == snapshot.weapon_usage_counts
    assert restored.quest_play_counts == tuple(0 for _ in range(int(QUEST_PLAY_COUNT)))
    assert restored.mode_play_survival == 0
    assert restored.mode_play_rush == 0
    assert restored.mode_play_typo == 0
    assert restored.mode_play_other == 0
    assert restored.game_sequence_id == 0
    assert restored.unknown_tail == (b"\x00" * int(UNKNOWN_TAIL_SIZE))


def test_game_status_from_progress_status_roundtrip() -> None:
    snapshot = ProgressStatusSnapshot(
        quest_unlock_index=11,
        quest_unlock_index_full=22,
        weapon_usage_counts=tuple([3] * int(WEAPON_USAGE_COUNT)),
        quest_play_counts=tuple([4] * int(QUEST_PLAY_COUNT)),
        mode_play_survival=10,
        mode_play_rush=20,
        mode_play_typo=30,
        mode_play_other=40,
        game_sequence_id=50,
        unknown_tail=b"\xEF" * int(UNKNOWN_TAIL_SIZE),
    )
    status = game_status_from_progress_status(snapshot, path=Path("replay://status"))
    restored = progress_status_from_game_status(status)
    assert restored == snapshot


def test_progress_hash_matches_lockstep_hash() -> None:
    snapshot = ProgressStatusSnapshot(
        quest_unlock_index=99,
        quest_unlock_index_full=199,
        weapon_usage_counts=tuple(range(int(WEAPON_USAGE_COUNT))),
    )
    wire = lockstep_status_from_progress(snapshot)
    assert hash_progress_status(snapshot) == hash_status_snapshot(wire)


def test_debug_progress_adapter_drops_non_debug_fields() -> None:
    snapshot = ProgressStatusSnapshot(
        quest_unlock_index=2,
        quest_unlock_index_full=4,
        weapon_usage_counts=tuple([7] * int(WEAPON_USAGE_COUNT)),
        quest_play_counts=tuple([8] * int(QUEST_PLAY_COUNT)),
        mode_play_survival=11,
        game_sequence_id=22,
    )
    debug_snapshot = debug_snapshot_from_progress_status(snapshot)
    restored = progress_status_from_debug_snapshot(debug_snapshot)

    assert restored.quest_unlock_index == snapshot.quest_unlock_index
    assert restored.quest_unlock_index_full == snapshot.quest_unlock_index_full
    assert restored.weapon_usage_counts == snapshot.weapon_usage_counts
    assert restored.quest_play_counts == tuple(0 for _ in range(int(QUEST_PLAY_COUNT)))
    assert restored.mode_play_survival == 0
    assert restored.game_sequence_id == 0


def test_progress_status_from_debug_snapshot_normalizes_counts() -> None:
    debug_snapshot = SnapshotStatus(
        quest_unlock_index=5,
        quest_unlock_index_full=9,
        weapon_usage_counts=[1, -1],
    )
    restored = progress_status_from_debug_snapshot(debug_snapshot)
    assert len(restored.weapon_usage_counts) == int(WEAPON_USAGE_COUNT)
    assert restored.weapon_usage_counts[0] == 1
    assert restored.weapon_usage_counts[1] == 0xFFFFFFFF
