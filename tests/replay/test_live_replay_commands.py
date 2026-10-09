from __future__ import annotations

import pytest

from crimson.game_modes import GameMode
from crimson.perks import PerkId
from crimson.replay import ReplayRecorder
from crimson.replay.driver.playback_driver import PlaybackDriver
from crimson.replay.input_codec import pack_tick
from crimson.sim.commands import PerkMenuOpenCommand, PerkPickCommand
from crimson.sim.run_spec import RunSpec
from grim.geom import Vec2
from tests.support.factories import player_input
from tests.support.replay_runner_helpers import unverified_replay
from tests.support.state_digest import session_digest


@pytest.mark.parametrize("perk", [PerkId.REFLEX_BOOSTED, PerkId.BANDAGE, PerkId.INSTANT_WINNER, PerkId.AMMO_MANIAC])
@pytest.mark.parametrize("reopen", [False, True])
def test_live_perk_commands_match_recorded_prelude(perk: PerkId, reopen: bool) -> None:
    recorder = ReplayRecorder(RunSpec(game_mode_id=GameMode.SURVIVAL, seed=0xBEEF))
    # The menu opened on the tick before: this tick picks, and may open it again for the next pending perk.
    commands = (PerkPickCommand(player_index=0, choice_index=0),) + ((PerkMenuOpenCommand(player_index=0),) if reopen else ())
    inputs = (player_input(move=Vec2(1.0, 0.0), aim=Vec2(600.0, 512.0)),)
    recorder.record(pack_tick(inputs, commands))
    replay = unverified_replay(recorder)
    live = PlaybackDriver(replay)
    playback = PlaybackDriver(replay)
    for driver in (live, playback):
        driver.session.perk_menu_open = True
        selection = driver.world.state.perk_selection
        selection.pending_count = 2
        selection.choices_dirty = False
        selection.choices = [perk] * 7

    live_tick = live.session.step_tick(dt=1 / 60, inputs=inputs, commands=commands)
    replay_tick = playback.step_tick(0).payload

    assert live_tick == replay_tick
    assert live.world.players == playback.world.players
    assert live.world.state.rng.state == playback.world.state.rng.state
    assert live.world.state.perk_selection == playback.world.state.perk_selection
    assert live.session.elapsed_ms == playback.session.elapsed_ms
    assert session_digest(live.session) == session_digest(playback.session)
    if perk == PerkId.REFLEX_BOOSTED:
        assert live.session.elapsed_ms == 15.0
