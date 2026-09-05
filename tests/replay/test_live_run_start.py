from __future__ import annotations

import pytest

from crimson.dbg.state_digest import session_state_bytes
from crimson.game_modes import GameMode
from crimson.modes import base_gameplay_mode, quest_mode
from crimson.modes.quest_mode import QuestMode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.modes.tutorial_mode import TutorialMode
from crimson.modes.typo_mode import TypoShooterMode
from crimson.persistence.save_status import GameStatus, GameStatusData
from crimson.quests.level import QuestLevel
from crimson.replay.driver.playback_driver import PlaybackDriver
from crimson.sim.input import PlayerInput
from crimson.sim.input_providers import TypoCharCommand
from grim.geom import Vec2
from grim.rand import Crand
from grim.view import ViewContext


@pytest.mark.parametrize(("game_mode", "mode_type"), [
    (GameMode.SURVIVAL, SurvivalMode), (GameMode.RUSH, RushMode), (GameMode.QUESTS, QuestMode),
    (GameMode.TUTORIAL, TutorialMode), (GameMode.TYPO, TypoShooterMode),
])
@pytest.mark.parametrize("player_count", [1, 4])
@pytest.mark.parametrize("preserve_bugs", [False, True])
def test_live_start_and_first_ticks_match_complete_replay_state(
    mocker, make_mode_config, assets_dir, tmp_path, game_mode, mode_type, player_count, preserve_bugs,
) -> None:
    mode = mode_type(
        ViewContext(assets_dir=assets_dir, preserve_bugs=preserve_bugs),
        config=make_mode_config(game_mode=game_mode, updates={"player_count": player_count, "detail_preset": 3, "violence_disabled": 1}),
        audio_rng=Crand(1),
    )
    status = GameStatus.from_data(path=tmp_path / "status.dat", data=GameStatusData(quest_unlock_index=15), dirty=False)
    mode.bind_status(status)
    mocker.patch.object(mode, "apply_terrain_setup")
    mocker.patch.object(mode.world_runtime, "open_runtime")
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=None)
    mocker.patch.object(quest_mode, "load_grim_mono_font", return_value=None)
    mode.open()
    if isinstance(mode, QuestMode):
        mode.start_run(QuestLevel(1, 1), status=status)
    session = mode._sim_session
    recorder = mode._replay_recorder
    assert session is not None and recorder is not None
    inputs = tuple(PlayerInput(aim=Vec2(600.0, 512.0), fire_down=True, move=Vec2(1.0, 0.0)) for _ in session.world.players)
    commands = (TypoCharCommand(player_index=0, ch="a"),) if game_mode == GameMode.TYPO else ()
    assert recorder.header.preserve_bugs == preserve_bugs
    for _ in range(3):
        recorder.record_tick(inputs, dt=1 / 60, commands=commands)
    driver = PlaybackDriver(recorder.finish(), version_mismatch_action=None)
    assert session.world.state.status is status
    assert session_state_bytes(session) == session_state_bytes(driver.session)
    for tick in range(3):
        live = session.step_tick(dt=1 / 60, inputs=inputs, commands=commands)
        replay = driver.step_tick(tick).payload
        assert live == replay
        assert session_state_bytes(session) == session_state_bytes(driver.session)
