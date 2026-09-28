import pytest

from crimson.game_modes import GameMode
from crimson.modes import base_gameplay_mode
from crimson.modes.rush_mode import RushMode
from crimson.modes.survival_mode import SurvivalMode
from crimson.modes.typo_mode import TypoShooterMode
from crimson.replay import ReplayRecorder
from crimson.screens.actions import Route
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


def _rush_with_hud_in(make_mode_config, assets_dir) -> RushMode:
    mode = RushMode(
        ViewContext(assets_dir=assets_dir), config=make_mode_config(game_mode=GameMode.RUSH), audio_rng=Crand(1),
    )
    mode.open()
    mode._ui_timeline.timeline_ms = mode._ui_timeline.max_timeline_ms
    return mode


def test_death_runs_the_world_while_the_hud_fades_out(mocker, make_mode_config, assets_dir) -> None:
    mode = _rush_with_hud_in(make_mode_config, assets_dir)
    session = mode._sim_session
    assert session is not None
    recorder = ReplayRecorder(RunSpec(game_mode_id=GameMode.RUSH, seed=1))
    game_over = mocker.patch.object(mode, "_enter_game_over")
    mode.player.health = 0.0

    ticks = 0
    while not game_over.called:
        mode._run_deterministic_session_ticks(dt_frame=1 / 60, session=session, recorder=recorder)
        ticks += 1

    # 500ms of timeline at 16ms a tick: the run's last tick and 31 more before game over.
    assert ticks == 32
    assert recorder.tick_index == 32
    assert session.elapsed_ms == 32 * 16.0


def test_escape_pauses_once_the_hud_has_faded_out(make_mode_config, assets_dir) -> None:
    mode = _rush_with_hud_in(make_mode_config, assets_dir)
    session = mode._sim_session
    assert session is not None

    mode._request_pause()
    for _ in range(31):
        mode._run_deterministic_session_ticks(dt_frame=1 / 60, session=session, recorder=None)
        assert mode.take_action() is None
    mode._run_deterministic_session_ticks(dt_frame=1 / 60, session=session, recorder=None)

    assert mode.take_action() is Route.PAUSE
    assert session.elapsed_ms == 32 * 16.0


def test_survival_world_runs_on_after_death_until_the_hud_has_faded(make_mode_config, assets_dir) -> None:
    mode = SurvivalMode(
        ViewContext(assets_dir=assets_dir), config=make_mode_config(game_mode=GameMode.SURVIVAL), audio_rng=Crand(1),
    )
    mode.open()
    mode._ui_timeline.timeline_ms = mode._ui_timeline.max_timeline_ms
    session = mode._sim_session
    assert session is not None
    mode.player.health = 0.0
    mode.player.death_timer = 0.0
    start_ms = session.elapsed_ms

    while not mode._game_over_active:
        mode.update(1 / 60)
        assert session.elapsed_ms - start_ms <= 40 * 16.0

    assert session.elapsed_ms - start_ms == 32 * 16.0


def test_rush_world_runs_on_after_the_last_death(make_mode_config, assets_dir) -> None:
    mode = _rush_with_hud_in(make_mode_config, assets_dir)
    session = mode._sim_session
    assert session is not None
    mode.player.health = 1.0
    attacker = mode.creatures.entries[0]
    attacker.active = True
    attacker.hp = 100.0
    attacker.size = 50.0
    attacker.pos = mode.player.pos
    attacker.contact_damage = 100.0

    while mode.player.health > 0.0:
        mode.update(1 / 60)
    died_at_ms = session.elapsed_ms
    while not mode._game_over_active:
        mode.update(1 / 60)
        assert session.elapsed_ms - died_at_ms <= 40 * 16.0

    # The death tick started the run-down; 31 more ticks ran before game over.
    assert session.elapsed_ms - died_at_ms == 31 * 16.0


def test_typo_opens_game_over_after_the_death_animation_and_the_hud_fade(make_mode_config, assets_dir) -> None:
    mode = TypoShooterMode(
        ViewContext(assets_dir=assets_dir), config=make_mode_config(game_mode=GameMode.TYPO), audio_rng=Crand(1),
    )
    mode.open()
    mode._ui_timeline.timeline_ms = mode._ui_timeline.max_timeline_ms
    mode.player.health = 0.0
    mode.player.death_timer = 0.0

    frames = 0
    while not mode._game_over_active:
        mode.update(1 / 60)
        frames += 1
        assert frames <= 40

    # One frame ends the death animation, then 500ms at 16ms a frame.
    assert frames == 32
