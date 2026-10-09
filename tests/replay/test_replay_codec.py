from __future__ import annotations

import re
import subprocess
from pathlib import Path

import msgspec
import pytest
import zstandard as zstd

import crimson
import crimson.replay.codec as replay_codec_mod
from crimson import game_version
from crimson.aim_schemes import AimScheme
from crimson.game_modes import GameMode
from crimson.game_version import REPLAY_FORMAT_VERSION, REPLAY_RULES, current_replay_game_version
from crimson.math_parity import f32
from crimson.movement_controls import MovementControlType
from crimson.quests.level import QuestLevel
from crimson.replay import (
    Replay,
    ReplayCodecError,
    ReplayGameVersionWarning,
    ReplayRecorder,
    ReplayTick,
    decode_replay_payload,
    dump_replay,
    encode_replay_payload,
    load_replay,
)
from crimson.replay import types as replay_types
from crimson.replay.driver.playback_driver import PlaybackDriver, build_verify_playback_driver
from crimson.replay.input_codec import pack_player_input, pack_tick, unpack_player_input
from crimson.replay.types import Pilot, Recorder
from crimson.replay.versioning import ReplayRulesError
from crimson.sim.commands import (
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
from tests.support.factories import player_input
from tests.support.replay_runner_helpers import idle_replay, replay_with_simulated_result


def _result(*, player_count: int = 1, outcome: RunOutcome = RunOutcome.DEATH, quest_final_ms: int | None = None) -> RunResult:
    return RunResult(
        outcome=outcome,
        elapsed_ms=1234,
        kills=5,
        shots_fired=10,
        shots_hit=4,
        rng_state=0xDEADBEEF,
        pending_perks=1,
        quest_final_ms=quest_final_ms,
        players=tuple(
            PlayerRunResult(
                experience=100 + index,
                health=-2.5,
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
        rules=REPLAY_RULES,
        recorder=Recorder(client="crimson", version="1.2.3", platform="macos-arm64"),
        pilot=None,
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
            status=RunStatus(quest_unlock_index=12, quest_unlock_index_hardcore=3),
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


@pytest.mark.parametrize(
    ("flags", "move_mode"),
    [
        (0, MovementControlType.DUAL_ACTION_PAD),
        (replay_types.MOVE_KEYS_PRESENT_FLAG | replay_types.MOVE_FORWARD_FLAG, MovementControlType.STATIC),
    ],
)
def test_inputs_recorded_without_controls_decode_to_the_controls_the_sim_ran(
    flags: int,
    move_mode: MovementControlType,
) -> None:
    decoded = unpack_player_input((0.0, 0.0, 512.0, 512.0, flags))
    assert (decoded.move_mode, decoded.aim_scheme) == (move_mode, AimScheme.MOUSE)
    assert unpack_player_input(pack_player_input(decoded)) == decoded


def test_replay_payload_layout() -> None:
    wire = _wire(
        _replay(ticks=[ReplayTick(inputs=[(0.0, 0.0, 1.0, 2.0, 0)], commands=[PerkPickCommand(player_index=0, choice_index=2)])]),
    )

    assert list(wire) == ["format_version", "game_version", "rules", "recorder", "pilot", "run", "result", "ticks"]
    assert wire["recorder"] == {"client": "crimson", "version": "1.2.3", "platform": "macos-arm64"}
    assert wire["pilot"] is None
    assert list(wire["run"]) == list(RunSpec.__struct_fields__)
    assert list(wire["result"]) == list(RunResult.__struct_fields__)
    assert wire["result"]["outcome"] == "death"
    assert wire["ticks"] == [[[[0.0, 0.0, 1.0, 2.0, 0]], [{"type": "perk_pick", "player_index": 0, "choice_index": 2}]]]


def test_recorder_builds_replay() -> None:
    run = RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1)
    recorder = ReplayRecorder(run, game_version="1.2.3")
    recorder.record(pack_tick([player_input(move=Vec2(1.0, 0.0), aim=Vec2(0.1, 456.0))]))

    replay = recorder.finish(_result())

    assert replay.run == run
    # The live game names itself and where it ran, apart from the rules version.
    assert (replay.recorder.client, replay.recorder.version) == ("crimson", current_replay_game_version())
    assert re.fullmatch(r"[a-z]+-[a-z0-9_]+", replay.recorder.platform)
    controls = (
        replay_types.MOVE_KEYS_PRESENT_FLAG
        | replay_types.MOVE_MODE_PRESENT_FLAG
        | MovementControlType.DUAL_ACTION_PAD << replay_types.MOVE_MODE_SHIFT
        | replay_types.AIM_SCHEME_PRESENT_FLAG
        | AimScheme.MOUSE << replay_types.AIM_SCHEME_SHIFT
    )
    assert replay.ticks[0].inputs == [(1.0, 0.0, float(f32(0.1)), 456.0, controls)]
    assert load_replay(dump_replay(replay)) == replay


def test_recorder_declares_the_pilot_a_harness_names(monkeypatch: pytest.MonkeyPatch) -> None:
    run = RunSpec(game_mode_id=GameMode.SURVIVAL, seed=1)
    assert ReplayRecorder(run).finish(_result()).pilot is None

    monkeypatch.setenv("CRIMSON_PILOT_NAME", "Astra")
    monkeypatch.setenv("CRIMSON_PILOT_MODEL", "gpt-5")

    assert ReplayRecorder(run).finish(_result()).pilot == Pilot(name="Astra", model="gpt-5")


# Envelope ------------------------------------------------------------------


def test_load_rejects_payload_over_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(replay_codec_mod, "MAX_REPLAY_PAYLOAD_BYTES", 4)
    with pytest.raises(ReplayCodecError, match="payload too large"):
        load_replay(zstd.ZstdCompressor(level=19).compress(b"12345"))


# Canonical encoding ----------------------------------------------------------


def _noncanonical_payloads() -> dict[str, bytes]:
    payload = _payload()

    # Top-level fixmap header 0x88 → 0x89 plus a repeated key.
    assert payload[0] == 0x88
    duplicate = b"\x89" + payload[1:] + msgspec.msgpack.encode("game_version") + msgspec.msgpack.encode("9.9.9")

    seed_key = msgspec.msgpack.encode("seed")
    non_minimal_int = payload.replace(seed_key + b"\x01", seed_key + b"\xcc\x01", 1)

    return {
        "duplicate key": duplicate,
        "non-minimal integer": non_minimal_int,
    }


@pytest.mark.parametrize("case", list(_noncanonical_payloads()))
def test_decode_rejects_noncanonical_payloads(case: str) -> None:
    payload = _noncanonical_payloads()[case]
    assert payload != _payload()
    with pytest.raises(ReplayCodecError):
        decode_replay_payload(payload)


@pytest.mark.parametrize(
    ("wire", "version"),
    [
        # 0.10.0 wrote v11, with the version inside a header map.
        ({"header": {"replay_format_version": 11, "seed": 1}, "inputs": []}, 11),
        ({**_wire(), "format_version": 28, "postlude": []}, 28),
    ],
)
def test_decode_names_the_format_of_another_version(wire: dict, version: int) -> None:
    with pytest.raises(ReplayCodecError, match=rf"format version: {version} \(this build reads versions 30, 31, {REPLAY_FORMAT_VERSION}\)"):
        decode_replay_payload(msgspec.msgpack.encode(wire))


@pytest.mark.parametrize(("version", "left_out"), [(30, {"rules", "pilot"}), (31, {"pilot"})])
def test_earlier_formats_read_with_what_they_left_out_and_are_written_as_the_current_format(version: int, left_out: set) -> None:
    wire = {key: value for key, value in _wire().items() if key not in left_out}
    wire["format_version"] = version

    replay = decode_replay_payload(msgspec.msgpack.encode(wire))

    assert (replay.format_version, replay.rules, replay.pilot) == (version, 1, None)
    assert encode_replay_payload(replay) == _payload()


def test_a_declared_pilot_round_trips() -> None:
    replay = msgspec.structs.replace(_replay(), pilot=Pilot(name="Astra", model="gpt-5", url="https://example.com/astra"))

    assert decode_replay_payload(encode_replay_payload(replay)) == replay


# Semantic validation -----------------------------------------------------------


@pytest.mark.parametrize(
    ("replay", "message"),
    [
        (_replay(RunSpec(game_mode_id=GameMode.DEMO, seed=1)), "not a replayable mode"),
        (_replay(ticks=[ReplayTick(inputs=[(0.1, 0.0, 0.0, 0.0, 0)])]), "canonical f32"),
    ],
)
def test_validation_rejects_invalid_replays(replay: Replay, message: str) -> None:
    with pytest.raises(ReplayCodecError, match=message):
        encode_replay_payload(replay)


# Game version -----------------------------------------------------------------


def test_a_replay_from_another_game_version_verifies_with_a_warning() -> None:
    replay = replay_with_simulated_result(idle_replay(30, run=RunSpec(game_mode_id=GameMode.SURVIVAL, seed=7)))
    older = msgspec.structs.replace(replay, game_version="0.0.1+gabc123def456")

    with pytest.warns(ReplayGameVersionWarning, match="another game version"):
        result = build_verify_playback_driver(older).run()

    assert result == replay.result


def _fake_git(monkeypatch: pytest.MonkeyPatch, *, tags: bytes, status: bytes) -> None:
    current_replay_game_version.cache_clear()
    monkeypatch.setattr(crimson, "__version__", "1.2.3")
    monkeypatch.setattr(game_version.shutil, "which", lambda _name: "/usr/bin/git")

    def _check_output(args: list[str], **_kwargs: object) -> bytes:
        match args[1]:
            case "rev-parse":
                return b"abcdef123456\n"
            case "tag":
                return tags
            case "status":
                return status
        raise AssertionError(f"unexpected git args: {args!r}")

    monkeypatch.setattr(game_version.subprocess, "check_output", _check_output)


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


def test_installed_package_inside_an_unrelated_repo_records_the_plain_version(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(tmp_path)]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "commit", "-q", "--allow-empty", "-m", "unrelated"], check=True)
    site_packages = tmp_path / ".venv" / "lib" / "python3.13" / "site-packages"
    (site_packages / "crimson" / "replay").mkdir(parents=True)
    current_replay_game_version.cache_clear()
    monkeypatch.setattr(crimson, "__version__", "1.2.3")
    monkeypatch.setattr(game_version, "__file__", str(site_packages / "crimson" / "game_version.py"))
    try:
        assert current_replay_game_version() == "1.2.3"
    finally:
        current_replay_game_version.cache_clear()


def test_load_rejects_large_zstd_window() -> None:
    payload = _payload()
    # Single raw block frame with a 16 MiB window descriptor.
    frame = b"\x28\xb5\x2f\xfd" + b"\x00" + b"\x70" + ((len(payload) << 3) | 1).to_bytes(3, "little") + payload
    with pytest.raises(ReplayCodecError, match="window exceeds 8 MiB"):
        load_replay(frame)


def test_a_replay_under_other_rules_decodes_but_does_not_play() -> None:
    other = msgspec.structs.replace(_replay(), rules=REPLAY_RULES + 1)

    assert decode_replay_payload(encode_replay_payload(other)).rules == REPLAY_RULES + 1
    with pytest.raises(ReplayRulesError, match="recorded under rules 2"):
        PlaybackDriver(other)
