from __future__ import annotations

import struct

import msgspec
import pytest
import zstandard as zstd

import crimson
import crimson.replay.codec as replay_codec_mod
from crimson.game_modes import GameMode
from crimson.math_parity import f32
from crimson.quests.level import QuestLevel
from crimson.replay import (
    Replay,
    ReplayCodecError,
    ReplayGameVersionError,
    ReplayGameVersionWarning,
    ReplayRecorder,
    ReplayTick,
    decode_replay_payload,
    dump_replay,
    encode_replay_payload,
    load_replay,
    warn_on_game_version_mismatch,
)
from crimson.replay import types as replay_types
from crimson.replay.types import REPLAY_FORMAT_VERSION, current_replay_game_version
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import (
    PerkMenuOpenCommand,
    PerkPickCommand,
    TypoBackspaceCommand,
    TypoCharCommand,
    TypoSubmitCommand,
)
from crimson.sim.run_result import PlayerRunResult, RunOutcome, RunResult
from crimson.sim.run_spec import RunSpec, RunStatus
from crimson.weapons import WeaponId
from grim.geom import Vec2


def _result(*, player_count: int = 1, outcome: RunOutcome = RunOutcome.DEATH, quest_final_ms: int | None = None) -> RunResult:
    return RunResult(
        outcome=outcome,
        elapsed_ms=1234,
        kills=5,
        rng_state=0xDEADBEEF,
        pending_perks=1,
        quest_final_ms=quest_final_ms,
        players=tuple(
            PlayerRunResult(
                experience=100 + index,
                health=-2.5,
                shots_fired=10,
                shots_hit=4,
                most_used_weapon_id=WeaponId.SHOTGUN,
            )
            for index in range(player_count)
        ),
    )


def _replay(
    run: RunSpec | None = None,
    *,
    ticks: list[ReplayTick] | None = None,
    result: RunResult | None = None,
) -> Replay:
    run = RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1) if run is None else run
    return Replay(
        format_version=REPLAY_FORMAT_VERSION,
        game_version="1.2.3",
        run=run,
        result=_result(player_count=run.player_count) if result is None else result,
        ticks=[ReplayTick(inputs=[(0.0, 0.0, 512.0, 512.0, 0)] * run.player_count)] if ticks is None else ticks,
    )


def _payload(replay: Replay | None = None) -> bytes:
    return encode_replay_payload(_replay() if replay is None else replay)


def _wire(replay: Replay | None = None) -> dict:
    value = msgspec.msgpack.decode(_payload(replay))
    assert isinstance(value, dict)
    return value


def test_replay_codec_roundtrip_all_command_kinds() -> None:
    survival = _replay(
        RunSpec(
            game_mode_id=GameMode.SURVIVAL,
            seed=0x1234,
            player_count=2,
            hardcore=True,
            demo=True,
            status=RunStatus(quest_unlock_index=12, quest_unlock_index_full=3),
        ),
        ticks=[
            ReplayTick(
                inputs=[(1.0, -1.0, 100.5, 200.25, 0x1003), (0.0, 0.0, 0.0, 0.0, 0)],
                commands=[PerkMenuOpenCommand(player_index=0), PerkPickCommand(player_index=1, choice_index=6)],
            ),
        ],
    )
    typo = _replay(
        RunSpec(
            game_mode_id=GameMode.TYPO,
            seed=7,
            typo_dictionary_words=("alpha", "beta"),
            typo_highscore_names=("ann",),
        ),
        ticks=[
            ReplayTick(
                inputs=[(0.0, 0.0, 512.0, 512.0, 0)],
                commands=[
                    TypoCharCommand(player_index=0, ch="a"),
                    TypoBackspaceCommand(player_index=0),
                    TypoSubmitCommand(player_index=0),
                ],
            ),
        ],
    )
    quest = _replay(
        RunSpec(game_mode_id=GameMode.QUESTS, seed=9, quest_level=QuestLevel(2, 7)),
        result=_result(outcome=RunOutcome.QUEST_COMPLETED, quest_final_ms=-250),
    )
    for replay in (survival, typo, quest):
        assert load_replay(dump_replay(replay)) == replay


def test_replay_payload_layout() -> None:
    wire = _wire(
        _replay(ticks=[ReplayTick(inputs=[(0.0, 0.0, 1.0, 2.0, 0)], commands=[PerkPickCommand(player_index=0, choice_index=2)])]),
    )

    assert list(wire) == ["format_version", "game_version", "run", "result", "ticks"]
    assert list(wire["run"]) == list(RunSpec.__struct_fields__)
    assert list(wire["result"]) == list(RunResult.__struct_fields__)
    assert wire["result"]["outcome"] == "death"
    assert wire["ticks"] == [[[[0.0, 0.0, 1.0, 2.0, 0]], [{"type": "perk_pick", "player_index": 0, "choice_index": 2}]]]


def test_replay_dump_is_deterministic() -> None:
    assert dump_replay(_replay()) == dump_replay(_replay())


def test_recorder_builds_replay() -> None:
    run = RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1)
    recorder = ReplayRecorder(run, game_version="1.2.3")
    recorder.record_tick([PlayerInput(move=Vec2(1.0, 0.0), aim=Vec2(0.1, 456.0))])

    replay = recorder.finish(_result())

    assert replay.run == run
    assert replay.ticks[0].inputs == [(1.0, 0.0, float(f32(0.1)), 456.0, 0)]
    assert load_replay(dump_replay(replay)) == replay


def test_recorder_validates_player_count() -> None:
    recorder = ReplayRecorder(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, player_count=2))
    with pytest.raises(ValueError, match="expected 2 player inputs"):
        recorder.record_tick([PlayerInput()])


# Envelope ------------------------------------------------------------------


def test_load_rejects_non_zstd_bytes() -> None:
    with pytest.raises(ReplayCodecError, match="zstd envelope"):
        load_replay(_payload())


def test_load_rejects_invalid_zstd_payload() -> None:
    with pytest.raises(ReplayCodecError, match="invalid replay zstd payload"):
        load_replay(b"\x28\xb5\x2f\xfdnot-a-zstd-stream")


@pytest.mark.parametrize("suffix", [b"trailing-garbage", zstd.ZstdCompressor().compress(b"second-frame")])
def test_load_rejects_data_after_zstd_frame(suffix: bytes) -> None:
    with pytest.raises(ReplayCodecError, match="invalid replay zstd payload"):
        load_replay(dump_replay(_replay()) + suffix)


def test_load_rejects_payload_over_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(replay_codec_mod, "MAX_REPLAY_PAYLOAD_BYTES", 4)
    with pytest.raises(ReplayCodecError, match="payload too large"):
        load_replay(zstd.ZstdCompressor(level=19).compress(b"12345"))


def test_load_rejects_file_over_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    data = dump_replay(_replay())
    monkeypatch.setattr(replay_codec_mod, "MAX_REPLAY_FILE_BYTES", len(data) - 1)
    with pytest.raises(ReplayCodecError, match="replay file too large"):
        load_replay(data)


# Canonical encoding ----------------------------------------------------------


def _noncanonical_payloads() -> dict[str, bytes]:
    payload = _payload()
    wire = _wire()

    reordered = dict(wire)
    reordered["run"] = dict(reversed(list(wire["run"].items())))

    missing = dict(wire)
    missing["run"] = {key: value for key, value in wire["run"].items() if key != "demo"}

    extra = dict(wire)
    extra["run"] = {**wire["run"], "tick_rate": 60}

    int_axis = dict(wire)
    int_axis["ticks"] = [[[[0, 0.0, 512.0, 512.0, 0]], []]]

    # Top-level fixmap header 0x85 → 0x86 plus a repeated key.
    assert payload[0] == 0x85
    duplicate = b"\x86" + payload[1:] + msgspec.msgpack.encode("game_version") + msgspec.msgpack.encode("9.9.9")

    seed_key = msgspec.msgpack.encode("seed")
    non_minimal_int = payload.replace(seed_key + b"\x01", seed_key + b"\xcc\x01", 1)
    float32 = payload.replace(b"\xcb" + struct.pack(">d", 512.0), b"\xca" + struct.pack(">f", 512.0), 1)

    return {
        "reordered keys": msgspec.msgpack.encode(reordered),
        "missing key": msgspec.msgpack.encode(missing),
        "extra key": msgspec.msgpack.encode(extra),
        "integer for float": msgspec.msgpack.encode(int_axis),
        "duplicate key": duplicate,
        "non-minimal integer": non_minimal_int,
        "float32 encoding": float32,
    }


@pytest.mark.parametrize("case", list(_noncanonical_payloads()))
def test_decode_rejects_noncanonical_payloads(case: str) -> None:
    payload = _noncanonical_payloads()[case]
    assert payload != _payload()
    with pytest.raises(ReplayCodecError):
        decode_replay_payload(payload)


def test_decode_accepts_canonical_payload() -> None:
    assert decode_replay_payload(_payload()) == _replay()


# Semantic validation -----------------------------------------------------------


@pytest.mark.parametrize(
    ("replay", "message"),
    [
        (msgspec.structs.replace(_replay(), format_version=19), "unsupported replay format version"),
        (msgspec.structs.replace(_replay(), game_version=""), "game_version"),
        (_replay(RunSpec(game_mode_id=GameMode.DEMO, seed=1)), "not a replayable mode"),
        (_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1 << 32)), "run.seed"),
        (_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=-1)), "run.seed"),
        (_replay(RunSpec(game_mode_id=GameMode.QUESTS, seed=1)), "quest_level"),
        (_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, quest_level=QuestLevel(1, 1))), "quest_level"),
        (_replay(RunSpec(game_mode_id=GameMode.TYPO, seed=1, player_count=2)), "player_count == 1"),
        (_replay(RunSpec(game_mode_id=GameMode.TUTORIAL, seed=1, player_count=2)), "player_count == 1"),
        (_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, detail_preset=1 << 31)), "run.detail_preset"),
        (_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, detail_preset=0)), "run.detail_preset"),
        (_replay(RunSpec(game_mode_id=GameMode.TYPO, seed=1, typo_dictionary_words=("x" * 16,))), "typo_dictionary_words"),
        (_replay(RunSpec(game_mode_id=GameMode.TYPO, seed=1, typo_dictionary_words=("é",))), "typo_dictionary_words"),
        (_replay(RunSpec(game_mode_id=GameMode.TYPO, seed=1, typo_dictionary_words=("a",) * 2049)), "at most 2048"),
        (_replay(RunSpec(game_mode_id=GameMode.TYPO, seed=1, typo_highscore_names=("a" * 32,))), "typo_highscore_names"),
        (_replay(RunSpec(game_mode_id=GameMode.TYPO, seed=1, typo_highscore_names=("ann1",))), "typo_highscore_names"),
        (_replay(RunSpec(game_mode_id=GameMode.TYPO, seed=1, typo_highscore_names=("a",) * 513)), "at most 512"),
        (_replay(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1, violence_disabled=256)), "run.violence_disabled"),
        (_replay(result=_result(player_count=2)), "result.players"),
        (_replay(result=_result(outcome=RunOutcome.QUEST_COMPLETED, quest_final_ms=1)), "invalid for survival"),
        (
            _replay(RunSpec(game_mode_id=GameMode.QUESTS, seed=1, quest_level=QuestLevel(1, 1)), result=_result(outcome=RunOutcome.QUEST_COMPLETED)),
            "quest_final_ms",
        ),
        (_replay(result=msgspec.structs.replace(_result(), rng_state=1 << 32)), "rng_state"),
        (_replay(ticks=[]), "at least one tick"),
        (_replay(ticks=[ReplayTick(inputs=[])]), "player inputs"),
        (_replay(ticks=[ReplayTick(inputs=[(float("nan"), 0.0, 0.0, 0.0, 0)])]), "must be finite"),
        (_replay(ticks=[ReplayTick(inputs=[(0.1, 0.0, 0.0, 0.0, 0)])]), "canonical f32"),
        (_replay(ticks=[ReplayTick(inputs=[(1e39, 0.0, 0.0, 0.0, 0)])]), "f32 range"),
        (_replay(ticks=[ReplayTick(inputs=[(0.0, 0.0, 0.0, 0.0, 1 << 24)])]), "unsupported bits"),
        (_replay(ticks=[ReplayTick(inputs=[(0.0, 0.0, 0.0, 0.0, 0x10)])]), "MOVE_KEYS_PRESENT"),
        (
            _replay(ticks=[ReplayTick(inputs=[(0.0, 0.0, 0.0, 0.0, 0)], commands=[PerkMenuOpenCommand(player_index=1)])]),
            "player_index",
        ),
        (
            _replay(
                ticks=[ReplayTick(inputs=[(0.0, 0.0, 0.0, 0.0, 0)], commands=[PerkPickCommand(player_index=0, choice_index=7)])],
            ),
            "choice_index",
        ),
        (
            _replay(ticks=[ReplayTick(inputs=[(0.0, 0.0, 0.0, 0.0, 0)], commands=[TypoSubmitCommand(player_index=0)])]),
            "Typ-o commands",
        ),
    ],
)
def test_validation_rejects_invalid_replays(replay: Replay, message: str) -> None:
    with pytest.raises(ReplayCodecError, match=message):
        encode_replay_payload(replay)


def test_decode_reports_schema_errors() -> None:
    wire = _wire()
    wire["ticks"] = [[[[0.0, 0.0, 0.0, 0.0, 0]], [{"type": "network_ping", "player_index": 0}]]]
    with pytest.raises(ReplayCodecError, match="invalid replay payload"):
        decode_replay_payload(msgspec.msgpack.encode(wire))


# Game version -----------------------------------------------------------------


def test_replay_version_mismatch_raises() -> None:
    replay = msgspec.structs.replace(_replay(), game_version="0.0.0")
    with pytest.raises(ReplayGameVersionError, match="mismatch"):
        warn_on_game_version_mismatch(replay, action="verification", current_version="1.0.0")


def test_replay_version_build_metadata_mismatch_warns() -> None:
    replay = msgspec.structs.replace(_replay(), game_version="1.0.0+gabc123")
    with pytest.warns(ReplayGameVersionWarning, match="build metadata differs"):
        warn_on_game_version_mismatch(replay, action="verification", current_version="1.0.0+gdef456")


def _fake_git(monkeypatch: pytest.MonkeyPatch, *, tags: bytes, status: bytes) -> None:
    current_replay_game_version.cache_clear()
    monkeypatch.setattr(crimson, "__version__", "1.2.3")
    monkeypatch.setattr(replay_types.shutil, "which", lambda _name: "/usr/bin/git")

    def _check_output(args: list[str], **_kwargs: object) -> bytes:
        match args[1]:
            case "rev-parse":
                return b"abcdef123456\n"
            case "tag":
                return tags
            case "status":
                return status
        raise AssertionError(f"unexpected git args: {args!r}")

    monkeypatch.setattr(replay_types.subprocess, "check_output", _check_output)


@pytest.mark.parametrize(
    ("tags", "status", "expected"),
    [
        (b"", b"", "1.2.3+gabcdef123456"),
        (b"v1.2.3\n", b"", "1.2.3"),
        (b"", b" M src/crimson/gameplay.py\n", "1.2.3+gabcdef123456.dirty"),
        (b"v1.2.3\n", b" M src/crimson/gameplay.py\n", "1.2.3+gabcdef123456.dirty"),
    ],
)
def test_current_replay_game_version(monkeypatch: pytest.MonkeyPatch, tags: bytes, status: bytes, expected: str) -> None:
    _fake_git(monkeypatch, tags=tags, status=status)
    try:
        assert current_replay_game_version() == expected
    finally:
        current_replay_game_version.cache_clear()


def test_load_rejects_large_zstd_window() -> None:
    payload = _payload()
    # Single raw block frame with a 16 MiB window descriptor.
    frame = b"\x28\xb5\x2f\xfd" + b"\x00" + b"\x70" + ((len(payload) << 3) | 1).to_bytes(3, "little") + payload
    with pytest.raises(ReplayCodecError, match="window exceeds 8 MiB"):
        load_replay(frame)


def test_dump_rejects_payload_over_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(replay_codec_mod, "MAX_REPLAY_PAYLOAD_BYTES", len(_payload()) - 1)
    with pytest.raises(ReplayCodecError, match="payload too large"):
        dump_replay(_replay())
