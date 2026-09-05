from __future__ import annotations

from pathlib import Path

from crimson.game_modes import GameMode
from crimson.modes import base_gameplay_mode
from crimson.modes.survival_mode import SurvivalMode
from crimson.screens.results.game_over import GameOverUi
from crimson.sim.sessions import DeterministicSession
from grim.rand import Crand
from grim.view import ViewContext


def test_survival_high_score_record_uses_player0_stats_in_multiplayer(mocker, make_mode_config) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    config = make_mode_config(game_mode=GameMode.SURVIVAL, updates={"player_count": 2})

    mode = SurvivalMode(ctx, config=config, audio_rng=Crand(0xBEEF))
    mocker.patch.object(mode, "apply_terrain_setup")
    mocker.patch.object(mode.world_runtime, "open_runtime")
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=None)
    mocker.patch.object(mode, "_save_replay")
    mode.open()
    mocker.patch.object(GameOverUi, "open", return_value=None)

    player0, player1 = mode.sim_world.players[:2]
    player0.experience = 1234
    player1.experience = 9999
    mode.state.highscore_score_xp = 1234

    mode.state.shots_fired[0] = 10
    mode.state.shots_hit[0] = 7
    mode.state.shots_fired[1] = 999
    mode.state.shots_hit[1] = 888

    mode.state.weapon_usage_time[1] = 5
    mode.state.weapon_shots_fired[1][2] = 999

    mode._enter_game_over()

    record = mode._game_over_record
    assert record is not None
    assert record.score_xp == 1234
    assert record.shots_fired == 10
    assert record.shots_hit == 7
    assert record.most_used_weapon_id == 1


def test_survival_elapsed_helpers_use_authoritative_session_timer(mocker, make_mode_config) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    ctx = ViewContext(assets_dir=repo_root / "artifacts" / "assets")
    mode = SurvivalMode(ctx, config=make_mode_config(game_mode=GameMode.SURVIVAL), audio_rng=Crand(0xBEEF))
    mocker.patch.object(mode, "apply_terrain_setup")
    mocker.patch.object(mode.world_runtime, "open_runtime")
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=None)
    mocker.patch.object(mode, "_save_replay")
    mode.open()
    session = mode._sim_session
    assert isinstance(session, DeterministicSession)
    session.elapsed_ms = 4321.0
    mocker.patch.object(GameOverUi, "open", return_value=None)

    mode._enter_game_over()

    record = mode._game_over_record
    assert record is not None
    assert record.survival_elapsed_ms == 4321
    assert mode._replay_checkpoint_elapsed_ms() == 4321.0
    assert mode._replay_claimed_stats_elapsed_ms() == 4321
