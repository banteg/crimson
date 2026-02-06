from __future__ import annotations

import gzip
import json

import pytest
from grim.geom import Vec2

from crimson.gameplay import PlayerInput
from crimson.replay import (
    PerkMenuOpenEvent,
    PerkPickEvent,
    ReplayCodecError,
    ReplayGameVersionWarning,
    ReplayHeader,
    ReplayRecorder,
    ReplayStatusSnapshot,
    dump_replay,
    load_replay,
    warn_on_game_version_mismatch,
)


def test_replay_codec_roundtrip() -> None:
    header = ReplayHeader(
        game_mode_id=1,
        seed=0x1234,
        tick_rate=60,
        difficulty_level=2,
        hardcore=True,
        preserve_bugs=True,
        world_size=1024.0,
        player_count=2,
        status=ReplayStatusSnapshot(quest_unlock_index=7, quest_unlock_index_full=40),
        input_quantization="raw",
    )
    rec = ReplayRecorder(header)
    rec.record_tick(
        [
            PlayerInput(move_x=1.0, aim=Vec2(10.25, 20.5), fire_down=True),
            PlayerInput(move_y=-1.0, aim=Vec2(99.0, 42.75), reload_pressed=True),
        ]
    )
    rec.record_perk_pick(player_index=0, choice_index=2, tick_index=1)
    rec.record_tick(
        [
            PlayerInput(move_x=0.0, move_y=0.0, aim=Vec2(11.0, 21.0), fire_pressed=True),
            PlayerInput(move_x=-1.0, move_y=0.0, aim=Vec2(100.0, 43.0)),
        ]
    )
    replay = rec.finish()

    blob = dump_replay(replay)
    decoded = load_replay(blob)

    assert decoded.version == 1
    assert decoded.header == header
    assert decoded.inputs == replay.inputs
    assert decoded.events == [PerkPickEvent(tick_index=1, player_index=0, choice_index=2)]


def test_replay_codec_roundtrip_perk_menu_open_event() -> None:
    header = ReplayHeader(game_mode_id=1, seed=0x1234, tick_rate=60, player_count=1)
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput()])
    rec.record_perk_menu_open(player_index=0, tick_index=1)
    rec.record_tick([PlayerInput()])
    replay = rec.finish()

    decoded = load_replay(dump_replay(replay))
    assert decoded.events == [PerkMenuOpenEvent(tick_index=1, player_index=0)]


def test_replay_codec_validates_event_tick_index_bounds() -> None:
    replay_obj = {
        "v": 1,
        "header": {"game_mode_id": 1, "seed": 1, "player_count": 1},
        "inputs": [[[0.0, 0.0, [0.0, 0.0], 0]]],
        "events": [[2, "perk_menu_open", 0]],
    }
    with pytest.raises(ReplayCodecError, match="out of bounds"):
        load_replay(json.dumps(replay_obj).encode("utf-8"))


def test_replay_codec_rejects_negative_event_tick_index() -> None:
    replay_obj = {
        "v": 1,
        "header": {"game_mode_id": 1, "seed": 1, "player_count": 1},
        "inputs": [[[0.0, 0.0, [0.0, 0.0], 0]]],
        "events": [[-1, "perk_menu_open", 0]],
    }
    with pytest.raises(ReplayCodecError, match="non-negative"):
        load_replay(json.dumps(replay_obj).encode("utf-8"))


def test_replay_dump_is_stable() -> None:
    header = ReplayHeader(game_mode_id=1, seed=1, player_count=1)
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput(move_x=1.0, aim=Vec2(123.0, 456.0))])
    replay = rec.finish()

    assert dump_replay(replay) == dump_replay(replay)


def test_replay_load_accepts_plain_json_bytes() -> None:
    header = ReplayHeader(game_mode_id=1, seed=1, player_count=1)
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput(move_x=1.0, aim=Vec2(123.0, 456.0))])
    replay = rec.finish()

    blob = dump_replay(replay)
    plain = gzip.decompress(blob)
    decoded = load_replay(plain)
    assert decoded.header == header


def test_replay_recorder_validates_player_count() -> None:
    header = ReplayHeader(game_mode_id=1, seed=1, player_count=2)
    rec = ReplayRecorder(header)
    with pytest.raises(ValueError, match="expected 2 player inputs"):
        rec.record_tick([PlayerInput()])


def test_replay_version_mismatch_warns() -> None:
    header = ReplayHeader(game_mode_id=1, seed=1, player_count=1, game_version="0.0.0")
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput()])
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning, match="mismatch"):
        assert warn_on_game_version_mismatch(replay, action="verification", current_version="1.0.0")
