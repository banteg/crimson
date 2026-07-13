from __future__ import annotations

from typing import cast

import msgspec
import pytest
import zstandard as zstd

import crimson
import crimson.replay.codec as replay_codec_mod
from crimson.game_modes import GameMode
from crimson.math_parity import f32
from crimson.persistence.save_status import GameStatusData
from crimson.replay import (
    ReplayClaimedStatsSnapshot,
    ReplayCodecError,
    ReplayGameVersionError,
    ReplayGameVersionWarning,
    ReplayHeader,
    ReplayRecorder,
    dump_replay,
    load_replay,
    warn_on_game_version_mismatch,
)
from crimson.replay import types as replay_types
from crimson.replay.types import (
    REPLAY_FORMAT_VERSION,
    ReplayCreatureSlotResidue,
    ReplayVec2,
    current_replay_game_version,
)
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    GameFrameRngAdvanceOperation,
    PerkMenuOpenCommand,
    PerkPickCommand,
    TypoBackspaceCommand,
    TypoCharCommand,
    TypoSubmitCommand,
)
from crimson.weapons import WeaponId
from grim.geom import Vec2


def _minimal_wire_replay_obj() -> dict[str, object]:
    recorder = ReplayRecorder(ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=1, player_count=1))
    recorder.record_tick([PlayerInput()])
    payload = zstd.ZstdDecompressor().decompress(dump_replay(recorder.finish()))
    value = msgspec.msgpack.decode(payload)
    assert isinstance(value, dict)
    return value


def _dump_wire(value: object) -> bytes:
    return zstd.ZstdCompressor(level=19).compress(msgspec.msgpack.encode(value))


def test_replay_codec_roundtrip() -> None:
    header = ReplayHeader(
        game_mode_id=GameMode.SURVIVAL,
        seed=0x1234,
        tick_rate=60,
        quest_fail_retry_count=2,
        hardcore=True,
        preserve_bugs=True,
        world_size=1024.0,
        player_count=2,
        status=GameStatusData(quest_unlock_index=7, quest_unlock_index_full=40),
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
    assert decoded.ticks[1].prelude == [PerkPickCommand(player_index=0, choice_index=2)]
    assert decoded.ticks[1].commands == []


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
    assert decoded.ticks[1].prelude == [PerkMenuOpenCommand(player_index=0)]
    assert decoded.ticks[1].commands == []


def test_replay_codec_roundtrip_postlude_menu_open() -> None:
    header = ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=0x1234, player_count=1)
    recorder = ReplayRecorder(header)
    recorder.record_tick(
        [PlayerInput()],
        postlude=[PerkMenuOpenCommand(player_index=0)],
    )

    decoded = load_replay(dump_replay(recorder.finish()))
    assert decoded.ticks[0].prelude == []
    assert decoded.ticks[0].postlude == [PerkMenuOpenCommand(player_index=0)]
    assert decoded.ticks[0].commands == []


def test_replay_codec_roundtrip_typo_commands_and_name_sources() -> None:
    header = ReplayHeader(
        game_mode_id=GameMode.TYPO,
        seed=0x1234,
        tick_rate=60,
        player_count=1,
        typo_dictionary_words=("amber", "onyx"),
        typo_highscore_names=("quick", "brown"),
    )
    rec = ReplayRecorder(header)
    rec.record_tick(
        [PlayerInput(aim=Vec2(512.0, 512.0))],
        commands=[TypoCharCommand(player_index=0, ch="a")],
    )
    rec.record_tick(
        [PlayerInput(aim=Vec2(512.0, 512.0))],
        commands=[TypoBackspaceCommand(player_index=0), TypoSubmitCommand(player_index=0)],
    )
    replay = rec.finish()

    decoded = load_replay(dump_replay(replay))

    assert decoded.header.typo_dictionary_words == ("amber", "onyx")
    assert decoded.header.typo_highscore_names == ("quick", "brown")
    assert decoded.ticks[0].commands == [TypoCharCommand(player_index=0, ch="a")]
    assert decoded.ticks[1].commands == [
        TypoBackspaceCommand(player_index=0),
        TypoSubmitCommand(player_index=0),
    ]


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
        load_replay(_dump_wire(replay_obj))


@pytest.mark.parametrize("bad_dt", [-1.0, float("inf"), float("nan")])
def test_replay_codec_rejects_invalid_dt_rows(bad_dt: float) -> None:
    replay_obj = _minimal_wire_replay_obj()
    replay_obj["ticks"] = [
        {
            "inputs": [[0.0, 0.0, 0.0, 0.0, 0]],
            "dt": bad_dt,
            "prelude": [],
            "postlude": [],
            "commands": [],
        },
    ]
    with pytest.raises(ReplayCodecError, match="must be finite and >= 0"):
        load_replay(_dump_wire(replay_obj))


@pytest.mark.parametrize("bad_input", [float("inf"), float("-inf"), float("nan"), 1e100])
def test_replay_codec_rejects_inputs_outside_f32(bad_input: float) -> None:
    replay_obj = _minimal_wire_replay_obj()
    replay_obj["ticks"] = [
        {
            "inputs": [[bad_input, 0.0, 0.0, 0.0, 0]],
            "dt": 1 / 60,
            "prelude": [],
            "postlude": [],
            "commands": [],
        },
    ]
    with pytest.raises(ReplayCodecError, match="must be finite|outside the f32 range"):
        load_replay(_dump_wire(replay_obj))


def test_replay_dump_rejects_nonfinite_input() -> None:
    header = ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=1, player_count=1)
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput()])
    replay = rec.finish()
    replay.ticks[0].inputs[0][2] = float("nan")

    with pytest.raises(ReplayCodecError, match="aim_x must be finite"):
        dump_replay(replay)


def test_replay_codec_rejects_noncanonical_envelope() -> None:
    with pytest.raises(ReplayCodecError, match="canonical zstd envelope"):
        load_replay(b'{"header":{"game_mode_id":1,"seed":1}}')


def test_replay_codec_rejects_unreplayable_demo_mode() -> None:
    recorder = ReplayRecorder(ReplayHeader(game_mode_id=GameMode.DEMO, seed=1))
    recorder.record_tick([PlayerInput()])

    with pytest.raises(ReplayCodecError, match="unsupported replay game_mode_id"):
        dump_replay(recorder.finish())


def test_replay_codec_rejects_invalid_zstd_payload() -> None:
    with pytest.raises(ReplayCodecError, match="invalid replay zstd payload"):
        load_replay(b"\x28\xb5\x2f\xfdnot-a-zstd-stream")


@pytest.mark.parametrize(
    "suffix",
    [b"trailing-garbage", zstd.ZstdCompressor().compress(b"second-frame")],
)
def test_replay_codec_rejects_data_after_zstd_frame(suffix: bytes) -> None:
    replay_obj = _minimal_wire_replay_obj()
    with pytest.raises(ReplayCodecError, match="invalid replay zstd payload"):
        load_replay(_dump_wire(replay_obj) + suffix)


def test_replay_codec_rejects_zstd_payload_over_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(replay_codec_mod, "MAX_REPLAY_PAYLOAD_BYTES", 4)
    payload = zstd.ZstdCompressor(level=19).compress(b"12345")
    with pytest.raises(ReplayCodecError, match="payload too large"):
        load_replay(payload)


def test_replay_codec_rejects_file_over_compressed_envelope_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = zstd.ZstdCompressor(level=19).compress(b"12345")
    monkeypatch.setattr(replay_codec_mod, "MAX_REPLAY_FILE_BYTES", len(payload) - 1)

    with pytest.raises(ReplayCodecError, match="replay file too large"):
        load_replay(payload)


def test_replay_dump_is_stable() -> None:
    header = ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=1, player_count=1)
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(123.0, 456.0))])
    replay = rec.finish()

    assert dump_replay(replay) == dump_replay(replay)


def test_replay_dump_canonicalizes_input_values_to_f32() -> None:
    header = ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=1, player_count=1)
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput()])
    replay = rec.finish()
    value = 0.123456789123
    replay.ticks[0].inputs[0][0] = value

    raw = zstd.ZstdDecompressor().decompress(dump_replay(replay))
    payload = cast("dict[str, object]", msgspec.msgpack.decode(raw))
    tick = cast("dict[str, object]", cast("list[object]", payload["ticks"])[0])
    packed = cast("list[list[float | int]]", tick["inputs"])[0]

    assert float(packed[0]) == float(f32(value))


def test_replay_dump_canonicalizes_header_and_pool_values() -> None:
    value = 1.0000000000000002
    header = ReplayHeader(
        game_mode_id=GameMode.SURVIVAL,
        seed=1,
        player_count=1,
        world_size=value,
        initial_creature_pool=(
            ReplayCreatureSlotResidue(
                index=0,
                phase_seed=383,
                pos=ReplayVec2(x=value, y=-value),
            ),
        ),
    )
    recorder = ReplayRecorder(header)
    recorder.record_tick([PlayerInput()])

    replay = load_replay(dump_replay(recorder.finish()))

    assert replay.header.world_size == float(f32(value))
    assert replay.header.initial_creature_pool is not None
    residue = replay.header.initial_creature_pool[0]
    assert residue.phase_seed == 383
    assert residue.pos.x == float(f32(value))
    assert residue.pos.y == float(f32(-value))


def test_replay_load_rejects_float_phase_seed() -> None:
    replay_obj = _minimal_wire_replay_obj()
    header = cast("dict[str, object]", replay_obj["header"])
    header["initial_creature_pool"] = [
        msgspec.to_builtins(ReplayCreatureSlotResidue(index=0, phase_seed=383)),
    ]
    residue = cast("dict[str, object]", cast("list[object]", header["initial_creature_pool"])[0])
    residue["phase_seed"] = 383.0

    with pytest.raises(ReplayCodecError, match="invalid replay msgpack payload"):
        load_replay(_dump_wire(replay_obj))


@pytest.mark.parametrize("field", ["state_flag", "collision_flag", "force_target"])
@pytest.mark.parametrize("value", [-1, 256])
def test_replay_rejects_pool_byte_out_of_range(field: str, value: int) -> None:
    header = ReplayHeader(
        game_mode_id=GameMode.SURVIVAL,
        seed=1,
        player_count=1,
        initial_creature_pool=(
            msgspec.structs.replace(ReplayCreatureSlotResidue(index=0), **{field: value}),
        ),
    )
    recorder = ReplayRecorder(header)
    recorder.record_tick([PlayerInput()])

    with pytest.raises(ReplayCodecError, match=field):
        dump_replay(recorder.finish())


def test_replay_load_rejects_plain_msgpack_bytes() -> None:
    header = ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=1, player_count=1)
    rec = ReplayRecorder(header)
    rec.record_tick([PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(123.0, 456.0))])
    replay = rec.finish()

    blob = dump_replay(replay)
    plain = zstd.ZstdDecompressor().decompress(blob)
    with pytest.raises(ReplayCodecError, match="canonical zstd envelope"):
        load_replay(plain)


def test_replay_load_rejects_older_format_version() -> None:
    replay_obj = _minimal_wire_replay_obj()
    replay_header = cast("dict[str, object]", replay_obj["header"])
    replay_header["replay_format_version"] = 9

    with pytest.raises(ReplayCodecError, match="unsupported replay format version: 9"):
        load_replay(_dump_wire(replay_obj))


def test_replay_load_rejects_unknown_and_missing_current_fields() -> None:
    replay_obj = _minimal_wire_replay_obj()
    header = cast("dict[str, object]", replay_obj["header"])
    header["bootstrap_kind"] = "none"
    with pytest.raises(ReplayCodecError, match=r"unknown=\['bootstrap_kind'\]"):
        load_replay(_dump_wire(replay_obj))

    replay_obj = _minimal_wire_replay_obj()
    tick = cast("dict[str, object]", cast("list[object]", replay_obj["ticks"])[0])
    del tick["commands"]
    with pytest.raises(ReplayCodecError, match=r"missing=\['commands'\]"):
        load_replay(_dump_wire(replay_obj))


def test_replay_load_rejects_reserved_input_flag_bits() -> None:
    replay_obj = _minimal_wire_replay_obj()
    tick = cast("dict[str, object]", cast("list[object]", replay_obj["ticks"])[0])
    inputs = cast("list[list[float | int]]", tick["inputs"])
    inputs[0][4] = 1 << 31

    with pytest.raises(ReplayCodecError, match="flags contain unsupported bits"):
        load_replay(_dump_wire(replay_obj))


@pytest.mark.parametrize(
    "flags",
    [
        1 << 4,
        1 << 9,
        (1 << 8) | (6 << 9),
        1 << 13,
        (1 << 12) | (6 << 13),
    ],
)
def test_replay_load_rejects_noncanonical_input_flag_payloads(flags: int) -> None:
    replay_obj = _minimal_wire_replay_obj()
    tick = cast("dict[str, object]", cast("list[object]", replay_obj["ticks"])[0])
    inputs = cast("list[list[float | int]]", tick["inputs"])
    inputs[0][4] = flags

    with pytest.raises(ReplayCodecError, match="flags"):
        load_replay(_dump_wire(replay_obj))


def test_replay_load_rejects_missing_quest_level_for_quest_mode() -> None:
    replay_obj = _minimal_wire_replay_obj()
    replay_header = cast("dict[str, object]", replay_obj["header"])
    replay_header["game_mode_id"] = int(GameMode.QUESTS)

    with pytest.raises(ReplayCodecError, match="quest replays require a valid header.quest_level"):
        load_replay(_dump_wire(replay_obj))


def test_replay_load_rejects_typo_multiplayer() -> None:
    replay_obj = _minimal_wire_replay_obj()
    replay_header = cast("dict[str, object]", replay_obj["header"])
    replay_header["game_mode_id"] = int(GameMode.TYPO)
    replay_header["player_count"] = 2

    with pytest.raises(ReplayCodecError, match="Typ-o replays require player_count == 1"):
        load_replay(_dump_wire(replay_obj))


def test_replay_load_rejects_out_of_range_player_count_via_msgspec_constraints() -> None:
    replay_obj = _minimal_wire_replay_obj()
    replay_header = cast("dict[str, object]", replay_obj["header"])
    replay_header["player_count"] = 0

    with pytest.raises(ReplayCodecError, match="invalid replay msgpack payload"):
        load_replay(_dump_wire(replay_obj))


@pytest.mark.parametrize("seed", [-1, 1 << 32])
def test_replay_codec_rejects_seed_outside_uint32(seed: int) -> None:
    replay_obj = _minimal_wire_replay_obj()
    replay_header = cast("dict[str, object]", replay_obj["header"])
    replay_header["seed"] = seed

    with pytest.raises(ReplayCodecError, match="seed must be a uint32"):
        load_replay(_dump_wire(replay_obj))

    header = ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=seed, player_count=1)
    recorder = ReplayRecorder(header)
    recorder.record_tick([PlayerInput()])
    with pytest.raises(ReplayCodecError, match="seed must be a uint32"):
        dump_replay(recorder.finish())


@pytest.mark.parametrize(
    "field",
    ["tick_rate", "quest_fail_retry_count", "detail_preset", "violence_disabled"],
)
def test_replay_codec_rejects_header_integers_outside_zig_i32(field: str) -> None:
    replay_obj = _minimal_wire_replay_obj()
    replay_header = cast("dict[str, object]", replay_obj["header"])
    replay_header[field] = 1 << 31

    with pytest.raises(ReplayCodecError, match=field):
        load_replay(_dump_wire(replay_obj))


@pytest.mark.parametrize("player_index", [-1, 1])
def test_replay_codec_rejects_prelude_player_outside_header_count(player_index: int) -> None:
    replay_obj = _minimal_wire_replay_obj()
    tick = cast("dict[str, object]", cast("list[object]", replay_obj["ticks"])[0])
    tick["prelude"] = [{"type": "perk_menu_open", "player_index": player_index}]

    with pytest.raises(ReplayCodecError, match="player_index"):
        load_replay(_dump_wire(replay_obj))


@pytest.mark.parametrize("player_index", [-1, 1])
def test_replay_codec_rejects_postlude_player_outside_header_count(player_index: int) -> None:
    replay_obj = _minimal_wire_replay_obj()
    tick = cast("dict[str, object]", cast("list[object]", replay_obj["ticks"])[0])
    tick["postlude"] = [{"type": "perk_menu_open", "player_index": player_index}]

    with pytest.raises(ReplayCodecError, match="postlude.*player_index"):
        load_replay(_dump_wire(replay_obj))


@pytest.mark.parametrize("choice_index", [-1, 7])
def test_replay_codec_rejects_invalid_perk_choice_index(choice_index: int) -> None:
    replay_obj = _minimal_wire_replay_obj()
    tick = cast("dict[str, object]", cast("list[object]", replay_obj["ticks"])[0])
    tick["prelude"] = [{"type": "perk_pick", "player_index": 0, "choice_index": choice_index}]

    with pytest.raises(ReplayCodecError, match="choice_index must be in 0..6"):
        load_replay(_dump_wire(replay_obj))


def test_replay_load_rejects_noncanonical_f32_inputs() -> None:
    move_x = 0.123456789123
    move_y = -0.987654321987
    aim_x = 321.123456789123
    aim_y = -654.987654321987

    replay_obj = _minimal_wire_replay_obj()
    replay_obj["ticks"] = [
        {
            "dt": 1 / 60,
            "inputs": [[move_x, move_y, aim_x, aim_y, 0]],
            "prelude": [],
            "postlude": [],
            "commands": [],
        },
    ]

    with pytest.raises(ReplayCodecError, match="must be canonical f32"):
        load_replay(_dump_wire(replay_obj))


def test_replay_codec_preserves_ordered_prelude() -> None:
    recorder = ReplayRecorder(ReplayHeader(game_mode_id=GameMode.SURVIVAL, seed=1, player_count=1))
    recorder.record_tick(
        [PlayerInput()],
        prelude=[GameFrameRngAdvanceOperation(frames=2)],
        commands=[
            PerkMenuOpenCommand(player_index=0),
            PerkPickCommand(player_index=0, choice_index=6),
        ],
    )

    replay = load_replay(dump_replay(recorder.finish()))

    assert replay.ticks[0].prelude == [
        GameFrameRngAdvanceOperation(frames=2),
        PerkMenuOpenCommand(player_index=0),
        PerkPickCommand(player_index=0, choice_index=6),
    ]


@pytest.mark.parametrize("frames", [0, -1])
def test_replay_codec_rejects_nonpositive_game_frame_rng_advance(frames: int) -> None:
    replay_obj = _minimal_wire_replay_obj()
    tick = cast("dict[str, object]", cast("list[object]", replay_obj["ticks"])[0])
    tick["prelude"] = [{"type": "game_frame_rng_advance", "frames": frames}]

    with pytest.raises(ReplayCodecError, match="frames must be in 1"):
        load_replay(_dump_wire(replay_obj))


def test_replay_codec_rejects_perk_operation_in_tick_commands() -> None:
    replay_obj = _minimal_wire_replay_obj()
    tick = cast("dict[str, object]", cast("list[object]", replay_obj["ticks"])[0])
    tick["commands"] = [{"type": "perk_menu_open", "player_index": 0}]

    with pytest.raises(ReplayCodecError, match="unsupported type 'perk_menu_open'"):
        load_replay(_dump_wire(replay_obj))


def test_replay_codec_rejects_game_frame_rng_advance_in_postlude() -> None:
    replay_obj = _minimal_wire_replay_obj()
    tick = cast("dict[str, object]", cast("list[object]", replay_obj["ticks"])[0])
    tick["postlude"] = [{"type": "game_frame_rng_advance", "frames": 1}]

    with pytest.raises(ReplayCodecError, match="postlude.*unsupported type 'game_frame_rng_advance'"):
        load_replay(_dump_wire(replay_obj))


def test_replay_codec_requires_postlude_field() -> None:
    replay_obj = _minimal_wire_replay_obj()
    tick = cast("dict[str, object]", cast("list[object]", replay_obj["ticks"])[0])
    tick.pop("postlude")

    with pytest.raises(ReplayCodecError, match=r"missing=\['postlude'\]"):
        load_replay(_dump_wire(replay_obj))


@pytest.mark.parametrize("field", ["dt", "move_x", "world_size"])
def test_replay_codec_rejects_integer_tokens_for_f32_fields(field: str) -> None:
    replay_obj = _minimal_wire_replay_obj()
    header = cast("dict[str, object]", replay_obj["header"])
    tick = cast("dict[str, object]", cast("list[object]", replay_obj["ticks"])[0])
    if field == "world_size":
        header["world_size"] = 1024
    elif field == "dt":
        tick["dt"] = 0
    else:
        packed = cast("list[object]", cast("list[object]", tick["inputs"])[0])
        packed[0] = 0

    with pytest.raises(ReplayCodecError, match="msgpack float"):
        load_replay(_dump_wire(replay_obj))


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
