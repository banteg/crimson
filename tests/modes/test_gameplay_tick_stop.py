from crimson.game_modes import GameMode
from crimson.modes import base_gameplay_mode
from crimson.modes.rush_mode import RushMode
from crimson.replay import ReplayHeader, ReplayRecorder
from crimson.sim.input import PlayerInput
from grim.rand import Crand
from grim.view import ViewContext


def test_death_stops_batch_and_records_final_tick_before_game_over(mocker, make_mode_config, assets_dir) -> None:
    mode = RushMode(
        ViewContext(assets_dir=assets_dir), config=make_mode_config(game_mode=GameMode.RUSH), audio_rng=Crand(1),
    )
    mocker.patch.object(mode, "apply_terrain_setup")
    mocker.patch.object(mode.world_runtime, "open_runtime")
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=None)
    mode.open()
    mocker.patch.object(mode, "_sync_audio_and_ground")
    mocker.patch.object(mode, "_build_local_inputs", return_value=[PlayerInput()])
    present = mocker.patch.object(base_gameplay_mode, "apply_presentation_outputs")
    recorder = ReplayRecorder(ReplayHeader(game_mode_id=GameMode.RUSH, seed=1))
    def check_finished_recording() -> None:
        assert recorder.tick_index == 1

    game_over = mocker.patch.object(mode, "_enter_game_over", side_effect=check_finished_recording)
    mode.player.health = 1.0
    attacker = mode.creatures.entries[0]
    attacker.active = True
    attacker.hp = 100.0
    attacker.size = 50.0
    attacker.pos = mode.player.pos
    attacker.contact_damage = 100.0
    session = mode._sim_session
    assert session is not None

    mode._run_deterministic_session_ticks(dt_frame=1 / 30, session=session, recorder=recorder)

    game_over.assert_called_once_with()
    assert mode.player.health <= 0.0
    assert recorder.tick_index == mode._tick_runner_next_tick_index == 1
    assert session.elapsed_ms == 16.0
    assert len(present.call_args.kwargs["outputs"]) == 1


def test_live_settings_change_does_not_change_recorded_session_settings(mocker, make_mode_config, assets_dir) -> None:
    mode = RushMode(ViewContext(assets_dir=assets_dir), config=make_mode_config(game_mode=GameMode.RUSH), audio_rng=Crand(1))
    mode.config.display.detail_preset = 5
    mode.config.display.violence_disabled = 0
    mocker.patch.object(mode, "apply_terrain_setup")
    mocker.patch.object(mode.world_runtime, "open_runtime")
    mocker.patch.object(base_gameplay_mode, "load_small_font", return_value=None)
    mode.open()
    mocker.patch.object(mode, "_sync_audio_and_ground")
    mocker.patch.object(mode, "_build_local_inputs", return_value=[PlayerInput()])
    mocker.patch.object(base_gameplay_mode, "apply_presentation_outputs")
    session = mode._sim_session
    assert session is not None
    mode.config.display.detail_preset = 1
    mode.config.display.violence_disabled = 1
    mode._run_deterministic_session_ticks(dt_frame=1 / 60, session=session, recorder=None)
    assert session.detail_preset == 5
    assert session.violence_disabled == 0
    prepared = mode._initialize_run(GameMode.RUSH)
    assert prepared.session.detail_preset == 1
    assert prepared.session.violence_disabled == 1
