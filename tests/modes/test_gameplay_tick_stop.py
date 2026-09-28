import pytest

from crimson.game_modes import GameMode
from crimson.modes import base_gameplay_mode
from crimson.modes.rush_mode import RushMode
from crimson.replay import ReplayRecorder
from crimson.sim.run_spec import RunSpec
from grim.rand import Crand
from grim.view import ViewContext

pytestmark = pytest.mark.usefixtures("headless_resources")


def test_death_stops_batch_and_records_final_tick_before_game_over(mocker, make_mode_config, assets_dir) -> None:
    mode = RushMode(
        ViewContext(assets_dir=assets_dir), config=make_mode_config(game_mode=GameMode.RUSH), audio_rng=Crand(1),
    )
    mode.open()
    present = mocker.spy(base_gameplay_mode, "apply_presentation_plans")
    recorder = ReplayRecorder(RunSpec(game_mode_id=GameMode.RUSH, seed=1))
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
    assert recorder.tick_index == 1
    assert session.elapsed_ms == 16.0
    assert len(present.call_args.kwargs["plans"]) == 1


def test_live_settings_change_does_not_change_recorded_session_settings(make_mode_config, assets_dir) -> None:
    mode = RushMode(ViewContext(assets_dir=assets_dir), config=make_mode_config(game_mode=GameMode.RUSH), audio_rng=Crand(1))
    mode.config.display.detail_preset = 5
    mode.config.display.violence_disabled = 0
    mode.open()
    session = mode._sim_session
    assert session is not None
    mode.config.display.detail_preset = 1
    mode.config.display.violence_disabled = 1
    mode._run_deterministic_session_ticks(dt_frame=1 / 60, session=session, recorder=None)
    assert session.world.state.detail_preset == 5
    assert session.world.state.violence_disabled == 0
    prepared = mode._initialize_run(GameMode.RUSH)
    assert prepared.session.world.state.detail_preset == 1
    assert prepared.session.world.state.violence_disabled == 1
