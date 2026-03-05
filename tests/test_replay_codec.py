from __future__ import annotations

from typing import cast

import msgspec
import pytest
import zstandard as zstd

import crimson
import crimson.replay.codec as replay_codec_mod
from crimson.game_modes import GameMode
from crimson.math_parity import f32
from crimson.replay import (
    ReplayClaimedStatsSnapshot,
    ReplayCodecError,
    ReplayGameVersionError,
    ReplayGameVersionWarning,
    ReplayHeader,
    ReplayRecorder,
    ReplayStatusSnapshot,
    dump_replay,
    load_replay,
    warn_on_game_version_mismatch,
)
from crimson.replay import types as replay_types
from crimson.replay.types import REPLAY_FORMAT_VERSION, WEAPON_USAGE_COUNT, current_replay_game_version
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import PerkMenuOpenCommand, PerkPickCommand
from crimson.weapons import WeaponId
from grim.geom import Vec2


def _minimal_wire_replay_obj() -> dict[str, object]:
    return {
        "header": {
            "game_mode_id": 1,
            "seed": 1,
            "replay_format_version": int(REPLAY_FORMAT_VERSION),
            "player_count": 1,
            "status": {
                "weapon_usage_counts": [0] * int(WEAPON_USAGE_COUNT),
            },
            "claimed_stats": {
                "complete": False,
                "ticks": 0,
                "elapsed_ms": 0,
                "score_xp": 0,
                "kills": 0,
                "most_used_weapon_id": 0,
                "shots_fired": 0,
                "shots_hit": 0,
            },
        },
        "ticks": [{"dt": 1 / 60, "inputs": [[0.0, 0.0, 0.0, 0.0, 0]]}],
    }


def test_replay_codec_roundtrip() -> None:
    header = ReplayHeader(
        game_mode_id=GameMode.SURVIVAL,
        seed=0x1234,
        tick_rate=60,
        difficulty_level=2,
        hardcore=True,
        preserve_bugs=True,
        world_size=1024.0,
        player_count=2,
        status=ReplayStatusSnapshot(quest_unlock_index=7, quest_unlock_index_full=40),
        input_quantization="f32",
    )
    rec = ReplayRecorder(header)
    rec.record_tick(
        [
            PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(10.25, 20.5), fire_down=True),
            PlayerInput(move=Vec2(0.0, -1.0), aim=Vec2(99.0, 42.75), reload_pressed=True),
        ],
    )
    rec.record_tick(
        [
            PlayerInput(move=Vec2(), aim=Vec2(11.0, 21.0), fire_pressed=True),
            PlayerInput(move=Vec2(-1.0, 0.0), aim=Vec2(100.0, 43.0)),
        ],
        commands=[PerkPickCommand(player_index=0, choice_index=2)],
    )
    replay = rec.finish()

    blob = dump_replay(replay)
    decoded = load_replay(blob)

    assert decoded.header.replay_format_version == int(REPLAY_FORMAT_VERSION)
    assert decoded.header == header
    assert len(decoded.ticks) == 2
    assert decoded.ticks[0].inputs == replay.ticks[0].inputs
    assert decoded.ticks[1].inputs == replay.ticks[1].inputs
    assert decoded.ticks[1].commands == [PerkPickCommand(player_index=0, choice_index=2)]


def test_replay_codec_roundtrip_perk_menu_open_command() -> None:
    header = ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=0x1234, tick_rate=60, player_count=1)
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput()])
    rec.record_tick(
        [PlayerInput()],
        commands=[PerkMenuOpenCommand(player_index=0)],
    )
    replay = rec.finish()

    decoded = load_replay(dump_replay(replay))
    assert decoded.ticks[1].commands == [PerkMenuOpenCommand(player_index=0)]


def test_replay_codec_roundtrip_claimed_stats() -> None:
    header = ReplayHeader(
        game_mode_id=GameMode.SURVIVAL,
        seed=0x1234,
        tick_rate=60,
        player_count=1,
        claimed_stats=ReplayClaimedStatsSnapshot(
            complete=True,
            ticks=1,
            elapsed_ms=16,
            score_xp=200,
            kills=3,
            most_used_weapon_id=WeaponId.MEAN_MINIGUN,
            shots_fired=9,
            shots_hit=8,
        ),
    )
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput()])
    replay = rec.finish()

    decoded = load_replay(dump_replay(replay))
    assert decoded.header.claimed_stats == header.claimed_stats


def test_replay_codec_rejects_invalid_claimed_stats() -> None:
    replay_obj = _minimal_wire_replay_obj()
    replay_header = cast("dict[str, object]", replay_obj["header"])
    replay_header["claimed_stats"] = {
        "complete": True,
        "ticks": 1,
        "elapsed_ms": 16,
        "score_xp": 0,
        "kills": 0,
        "most_used_weapon_id": 1,
        "shots_fired": 1,
        "shots_hit": 2,
    }
    with pytest.raises(ReplayCodecError, match="claimed_stats.shots_hit must be <= claimed_stats.shots_fired"):
        load_replay(msgspec.msgpack.encode(replay_obj))


@pytest.mark.parametrize("bad_dt", [-1.0, float("inf"), float("nan")])
def test_replay_codec_rejects_invalid_dt_rows(bad_dt: float) -> None:
    replay_obj = _minimal_wire_replay_obj()
    replay_obj["ticks"] = [{"inputs": [[0.0, 0.0, 0.0, 0.0, 0]], "dt": bad_dt}]
    with pytest.raises(ReplayCodecError, match="must be finite and >= 0"):
        load_replay(msgspec.msgpack.encode(replay_obj))


def test_replay_codec_rejects_legacy_json_payload() -> None:
    with pytest.raises(ReplayCodecError, match="legacy JSON replay format is unsupported"):
        load_replay(b'{"header":{"game_mode_id":1,"seed":1}}')


def test_replay_codec_rejects_invalid_zstd_payload() -> None:
    with pytest.raises(ReplayCodecError, match="invalid replay zstd payload"):
        load_replay(b"\x28\xb5\x2f\xfdnot-a-zstd-stream")


def test_replay_codec_rejects_zstd_payload_over_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(replay_codec_mod, "_DEFAULT_MAX_REPLAY_PAYLOAD_BYTES", 4)
    payload = zstd.ZstdCompressor(level=19).compress(b"12345")
    with pytest.raises(ReplayCodecError, match="payload too large"):
        load_replay(payload)


def test_replay_dump_is_stable() -> None:
    header = ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=1, player_count=1)
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(123.0, 456.0))])
    replay = rec.finish()

    assert dump_replay(replay) == dump_replay(replay)


def test_replay_load_accepts_plain_msgpack_bytes() -> None:
    header = ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=1, player_count=1)
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(123.0, 456.0))])
    replay = rec.finish()

    blob = dump_replay(replay)
    plain = zstd.ZstdDecompressor().decompress(blob)
    decoded = load_replay(plain)
    assert decoded.header == header


def test_replay_load_quantizes_inputs_when_header_requests_f32() -> None:
    move_x = 0.123456789123
    move_y = -0.987654321987
    aim_x = 321.123456789123
    aim_y = -654.987654321987

    replay_obj: dict[str, object] = {
        "header": {
            "game_mode_id": 1,
            "seed": 1,
            "replay_format_version": int(REPLAY_FORMAT_VERSION),
            "player_count": 1,
            "input_quantization": "f32",
            "status": {
                "weapon_usage_counts": [0] * int(WEAPON_USAGE_COUNT),
            },
            "claimed_stats": {
                "complete": False,
                "ticks": 1,
                "elapsed_ms": 16,
                "score_xp": 0,
                "kills": 0,
                "most_used_weapon_id": 0,
                "shots_fired": 0,
                "shots_hit": 0,
            },
        },
        "ticks": [{"dt": 1 / 60, "inputs": [[move_x, move_y, aim_x, aim_y, 0]]}],
    }

    replay = load_replay(msgspec.msgpack.encode(replay_obj))

    packed = replay.ticks[0].inputs[0]
    move_x_loaded = packed[0]
    move_y_loaded = packed[1]
    aim_x_loaded = packed[2]
    aim_y_loaded = packed[3]
    assert isinstance(move_x_loaded, int | float)
    assert isinstance(move_y_loaded, int | float)
    assert isinstance(aim_x_loaded, int | float)
    assert isinstance(aim_y_loaded, int | float)

    assert float(move_x_loaded) == float(f32(move_x))
    assert float(move_y_loaded) == float(f32(move_y))
    assert float(aim_x_loaded) == float(f32(aim_x))
    assert float(aim_y_loaded) == float(f32(aim_y))


def test_replay_recorder_validates_player_count() -> None:
    header = ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=1, player_count=2)
    rec = ReplayRecorder(header)
    with pytest.raises(ValueError, match="expected 2 player inputs"):
        rec.record_tick([PlayerInput()])


def test_replay_version_mismatch_raises() -> None:
    header = ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=1, player_count=1, game_version="0.0.0")
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput()])
    replay = rec.finish()

    with pytest.raises(ReplayGameVersionError, match="mismatch"):
        warn_on_game_version_mismatch(replay, action="verification", current_version="1.0.0")


def test_replay_version_build_metadata_mismatch_warns() -> None:
    header = ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=1, player_count=1, game_version="1.0.0+gabc123")
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput()])
    replay = rec.finish()

    with pytest.warns(ReplayGameVersionWarning, match="build metadata differs"):
        warn_on_game_version_mismatch(replay, action="verification", current_version="1.0.0+gdef456")


def test_current_replay_game_version_appends_git_sha_for_non_release_head(monkeypatch: pytest.MonkeyPatch) -> None:
    current_replay_game_version.cache_clear()
    monkeypatch.setattr(crimson, "__version__", "1.2.3")
    monkeypatch.setattr(replay_types.shutil, "which", lambda _name: "/usr/bin/git")

    def _check_output(args: list[str], **_kwargs: object) -> bytes:
        if len(args) >= 3 and args[1] == "rev-parse":
            return b"abcdef123456\n"
        if len(args) >= 2 and args[1] == "tag":
            return b""
        raise AssertionError(f"unexpected git args: {args!r}")

    monkeypatch.setattr(replay_types.subprocess, "check_output", _check_output)

    assert current_replay_game_version() == "1.2.3+gabcdef123456"
    current_replay_game_version.cache_clear()


def test_current_replay_game_version_keeps_plain_version_on_release_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    current_replay_game_version.cache_clear()
    monkeypatch.setattr(crimson, "__version__", "1.2.3")
    monkeypatch.setattr(replay_types.shutil, "which", lambda _name: "/usr/bin/git")

    def _check_output(args: list[str], **_kwargs: object) -> bytes:
        if len(args) >= 3 and args[1] == "rev-parse":
            return b"abcdef123456\n"
        if len(args) >= 2 and args[1] == "tag":
            return b"v1.2.3\n"
        raise AssertionError(f"unexpected git args: {args!r}")

    monkeypatch.setattr(replay_types.subprocess, "check_output", _check_output)

    assert current_replay_game_version() == "1.2.3"
    current_replay_game_version.cache_clear()
