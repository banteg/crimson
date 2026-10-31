"""Historical rules select behavior, including the unversioned co-op reload exception."""

from pathlib import Path

import msgspec
import pytest

from crimson.cl_build import ClBuild
from crimson.replay.codec import load_replay_file
from crimson.replay.driver.playback_driver import PlaybackDriver, ReplayRunnerError
from crimson.replay.recorder import ReplayRecorder
from crimson.replay.versioning import legacy_coop_reload
from crimson.sim.run_init import initialize_run
from crimson.weapon_runtime import weapon_assign_player
from crimson.weapons import WeaponId
from tests.support.factories import player_input, step_player

FIXTURE = Path("tests/fixtures/replays/quest-1.1-completed.crd")


@pytest.mark.parametrize("rules", [1, 2])
def test_profile_survives_keyframes_and_recording(rules):
    replay = msgspec.structs.replace(load_replay_file(FIXTURE), rules=rules)
    driver = PlaybackDriver(replay, warn_on_version_mismatch=False)
    assert driver.world.state.rules == rules
    saved = driver.keyframe_state()
    driver.world.state.rules = 3 - rules
    driver.restore(saved)
    assert driver.world.state.rules == rules
    assert driver.world.state.rules2_fixes == (rules == 2)
    recorder = ReplayRecorder(replay.run, rules=driver.world.state.rules)
    recorder.record(replay.ticks[0])
    assert recorder.finish(replay.result).rules == rules
    # A fresh ordinary run returns to the current default.
    assert initialize_run(replay.run).session.world.state.rules == 2


@pytest.mark.parametrize("version,legacy", [("0.17.0", True), ("0.18.0", True), ("0.19.0", False), ("0.19.2+build.abc", False)])
def test_historical_coop_manual_reload(version, legacy):
    replay = load_replay_file(FIXTURE)
    replay = msgspec.structs.replace(replay, game_version=version, run=msgspec.structs.replace(replay.run, player_count=2))
    assert legacy_coop_reload(replay) is legacy
    world = initialize_run(replay.run, rules=1, legacy_coop_reload=legacy_coop_reload(replay)).session.world
    player = world.players[0]
    weapon_assign_player(player, WeaponId.PISTOL, state=world.state)
    player.weapon.ammo = 1
    step_player(world, player, player_input(reload_down=True), 0.01)
    assert (player.weapon.reload_timer > 0) is (not legacy)


def test_ambiguous_development_coop_build_is_not_guessed():
    replay = load_replay_file(FIXTURE)
    replay = msgspec.structs.replace(replay, game_version="0.18.0+build.unknown", run=msgspec.structs.replace(replay.run, player_count=2))
    with pytest.raises(ReplayRunnerError, match="provenance"):
        PlaybackDriver(replay, warn_on_version_mismatch=False)
    # The exception does not affect solo or original behavior.
    assert not legacy_coop_reload(msgspec.structs.replace(replay, run=msgspec.structs.replace(replay.run, preserve_bugs=True)))
    assert not legacy_coop_reload(msgspec.structs.replace(replay, rules=2))


@pytest.mark.parametrize("version", ["0.18.0", "0.18.0+build.0123456789abcdef01234567"])
def test_recorded_coop_seats_postdate_the_manual_reload_fix(version):
    replay = load_replay_file(Path("tests/fixtures/replays/rules1-ranked-coop.crd"))
    replay = msgspec.structs.replace(replay, game_version=version)
    assert replay.seat_keys is not None
    assert not legacy_coop_reload(replay)
    driver = PlaybackDriver(replay, warn_on_version_mismatch=False)
    assert not driver.world.state.legacy_coop_reload


def test_a_1_9_8_run_does_not_play_under_rules_1():
    # The codec refuses such a file; a replay built in memory meets the run's own check.
    replay = load_replay_file(FIXTURE)
    replay = msgspec.structs.replace(replay, rules=1, run=msgspec.structs.replace(replay.run, cl_build=ClBuild.V1_9_8))
    with pytest.raises(ReplayRunnerError, match="1.9.8 rules need rules 2"):
        PlaybackDriver(replay, warn_on_version_mismatch=False)
